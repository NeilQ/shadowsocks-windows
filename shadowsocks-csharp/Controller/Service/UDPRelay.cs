using System;
using System.Collections.Generic;
using System.Text;
using Shadowsocks.Encryption;
using Shadowsocks.Model;
using System.Net.Sockets;
using System.Net;
using System.Runtime.CompilerServices;
using Shadowsocks.Controller.Strategy;

namespace Shadowsocks.Controller
{
    /*
         SOCKS5 UDP Request
         +----+------+------+----------+----------+----------+
         |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
         +----+------+------+----------+----------+----------+
         | 2  |  1   |  1   | Variable |    2     | Variable |
         +----+------+------+----------+----------+----------+

         SOCKS5 UDP Response
         +----+------+------+----------+----------+----------+
         |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
         +----+------+------+----------+----------+----------+
         | 2  |  1   |  1   | Variable |    2     | Variable |
         +----+------+------+----------+----------+----------+

         shadowsocks UDP Request (before encrypted)
         +------+----------+----------+----------+
         | ATYP | DST.ADDR | DST.PORT |   DATA   |
         +------+----------+----------+----------+
         |  1   | Variable |    2     | Variable |
         +------+----------+----------+----------+

         shadowsocks UDP Response (before encrypted)
         +------+----------+----------+----------+
         | ATYP | DST.ADDR | DST.PORT |   DATA   |
         +------+----------+----------+----------+
         |  1   | Variable |    2     | Variable |
         +------+----------+----------+----------+

         shadowsocks UDP Request and Response (after encrypted)
         +-------+--------------+
         |   IV  |    PAYLOAD   |
         +-------+--------------+
         | Fixed |   Variable   |
         +-------+--------------+
*/

    /// <summary>
    /// udp socket转发，实现本地与ss服务器的udp数据隧道逻辑
    /// </summary>
    class UDPRelay : Listener.Service
    {
        private ShadowsocksController _controller;
        private LRUCache<IPEndPoint, UDPHandler> _cache;
        public UDPRelay(ShadowsocksController controller)
        {
            this._controller = controller;
            this._cache = new LRUCache<IPEndPoint, UDPHandler>(512);  // todo: choose a smart number
        }

        public bool Handle(byte[] firstPacket, int length, Socket socket, object state)
        {
            if (socket.ProtocolType != ProtocolType.Udp)
            {
                return false;
            }
            if (length < 4)
            {
                return false;
            }
            Listener.UDPState udpState = (Listener.UDPState)state;
            IPEndPoint remoteEndPoint = (IPEndPoint)udpState.remoteEndPoint;
            UDPHandler handler = _cache.get(remoteEndPoint);
            if (handler == null)
            {
                handler = new UDPHandler(socket, _controller.GetAServer(IStrategyCallerType.UDP, remoteEndPoint), remoteEndPoint);
                _cache.add(remoteEndPoint, handler);
            }
            handler.Send(firstPacket, length);
            handler.Receive();
            return true;
        }

        public class UDPHandler
        {
            private Socket _local;  // 与客户端本地交互的udp socket
            private Socket _remote; // 与ss服务器交互的udp socket

            private Server _server; // ss服务器信息
            private byte[] _buffer = new byte[1500];

            private IPEndPoint _localEndPoint;  // 客户端本地ip：端口(发起这个socket请求的端，并非127.0.0.1:1080)
            private IPEndPoint _remoteEndPoint;  // ss服务器ip：端口

            public UDPHandler(Socket local, Server server, IPEndPoint localEndPoint)
            {
                _local = local;
                _server = server;
                _localEndPoint = localEndPoint;

                // TODO async resolving
                // 解析ss服务器ip地址
                IPAddress ipAddress;
                bool parsed = IPAddress.TryParse(server.server, out ipAddress);
                if (!parsed)
                {
                    IPHostEntry ipHostInfo = Dns.GetHostEntry(server.server);
                    ipAddress = ipHostInfo.AddressList[0];
                }
                _remoteEndPoint = new IPEndPoint(ipAddress, server.server_port);
                _remote = new Socket(_remoteEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);

            }

            /// <summary>
            /// 处理数据,并发送给ss服务器
            /// </summary>
            /// <param name="data"></param>
            /// <param name="length"></param>
            public void Send(byte[] data, int length)
            {
                /*
                +----+------+------+----------+----------+----------+
                |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
                +----+------+------+----------+----------+----------+
                | 2  |  1   |  1   | Variable |    2     | Variable |
                +----+------+------+----------+----------+----------+

                trim => (去掉前三位，猜测是无用信息，减小数据大小/网络开销)

                +------+----------+----------+----------+
                | ATYP | DST.ADDR | DST.PORT |   DATA   |
                +------+----------+----------+----------+
                |  1   | Variable |    2     | Variable |
                +------+----------+----------+----------+

                encrypt => (加密)

                +-------+--------------+
                |   IV  |    PAYLOAD   |
                +-------+--------------+
                | Fixed |   Variable   |
                +-------+--------------+
                */
                // 去掉前三个字节
                IEncryptor encryptor = EncryptorFactory.GetEncryptor(_server.method, _server.password, _server.auth, true);
                byte[] dataIn = new byte[length - 3 + IVEncryptor.ONETIMEAUTH_BYTES];
                Array.Copy(data, 3, dataIn, 0, length - 3);
                byte[] dataOut = new byte[length - 3 + 16 + IVEncryptor.ONETIMEAUTH_BYTES];
                int outlen;
                // 加密
                encryptor.Encrypt(dataIn, length - 3, dataOut, out outlen);
                Logging.Debug($"++++++Send Server Port, size:" + outlen);
                // 发送给ss服务器
                _remote.SendTo(dataOut, outlen, SocketFlags.None, _remoteEndPoint);
            }

            /// <summary>
            /// 从ss服务器待接收数据
            /// </summary>
            public void Receive()
            {
                // 数据来源
                EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                Logging.Debug($"++++++Receive Server Port, size:" + _buffer.Length);
                _remote.BeginReceiveFrom(_buffer, 0, _buffer.Length, 0, ref remoteEndPoint, new AsyncCallback(RecvFromCallback), null);
            }

            /// <summary>
            /// 从ss服务器接收数据后的回调方法，
            /// 接收数据后, 发送回客户端的udp socket
            /// </summary>
            /// <param name="ar"></param>
            public void RecvFromCallback(IAsyncResult ar)
            {
                /*
                +-------+--------------+
                |   IV  |    PAYLOAD   |
                +-------+--------------+
                | Fixed |   Variable   |
                +-------+--------------+
                ->decrypt 解密

                +------+----------+----------+----------+
                | ATYP | DST.ADDR | DST.PORT |   DATA   |
                +------+----------+----------+----------+
                |  1   | Variable |    2     | Variable |
                +------+----------+----------+----------+
                ->add 包装协议内容

                +----+------+------+----------+----------+----------+
                |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
                +----+------+------+----------+----------+----------+
                | 2  |  1   |  1   | Variable |    2     | Variable |
                +----+------+------+----------+----------+----------+
                */
                try
                {
                    EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                    int bytesRead = _remote.EndReceiveFrom(ar, ref remoteEndPoint);

                    byte[] dataOut = new byte[bytesRead];
                    int outlen;

                    // 解密
                    IEncryptor encryptor = EncryptorFactory.GetEncryptor(_server.method, _server.password, _server.auth, true);
                    encryptor.Decrypt(_buffer, bytesRead, dataOut, out outlen);

                    // 包装socks5协议
                    byte[] sendBuf = new byte[outlen + 3];
                    Array.Copy(dataOut, 0, sendBuf, 3, outlen);

                    Logging.Debug($"======Send Local Port, size:" + (outlen + 3));
                    // 将数据转发给客户端socket
                    _local.SendTo(sendBuf, outlen + 3, 0, _localEndPoint);

                    // 继续等待ss服务器的数据
                    Receive();
                }
                catch (ObjectDisposedException)
                {
                    // TODO: handle the ObjectDisposedException
                }
                catch (Exception)
                {
                    // TODO: need more think about handle other Exceptions, or should remove this catch().
                }
                finally
                {
                }
            }
            public void Close()
            {
                try
                {
                    _remote.Close();
                }
                catch (ObjectDisposedException)
                {
                    // TODO: handle the ObjectDisposedException
                }
                catch (Exception)
                {
                    // TODO: need more think about handle other Exceptions, or should remove this catch().
                }
                finally
                {
                }
            }
        }
    }


    // cc by-sa 3.0 http://stackoverflow.com/a/3719378/1124054
    /// <summary>
    /// 最近最少使用缓存的c#实现。(Least Recently Used)
    /// </summary>
    /// <typeparam name="K"></typeparam>
    /// <typeparam name="V"></typeparam>
    class LRUCache<K, V> where V : UDPRelay.UDPHandler
    {
        private int capacity;
        private Dictionary<K, LinkedListNode<LRUCacheItem<K, V>>> cacheMap = new Dictionary<K, LinkedListNode<LRUCacheItem<K, V>>>();
        private LinkedList<LRUCacheItem<K, V>> lruList = new LinkedList<LRUCacheItem<K, V>>();

        public LRUCache(int capacity)
        {
            this.capacity = capacity;
        }

        [MethodImpl(MethodImplOptions.Synchronized)]
        public V get(K key)
        {
            LinkedListNode<LRUCacheItem<K, V>> node;
            if (cacheMap.TryGetValue(key, out node))
            {
                V value = node.Value.value;
                lruList.Remove(node);
                lruList.AddLast(node);
                return value;
            }
            return default(V);
        }

        [MethodImpl(MethodImplOptions.Synchronized)]
        public void add(K key, V val)
        {
            if (cacheMap.Count >= capacity)
            {
                RemoveFirst();
            }

            LRUCacheItem<K, V> cacheItem = new LRUCacheItem<K, V>(key, val);
            LinkedListNode<LRUCacheItem<K, V>> node = new LinkedListNode<LRUCacheItem<K, V>>(cacheItem);
            lruList.AddLast(node);
            cacheMap.Add(key, node);
        }

        private void RemoveFirst()
        {
            // Remove from LRUPriority
            LinkedListNode<LRUCacheItem<K, V>> node = lruList.First;
            lruList.RemoveFirst();

            // Remove from cache
            cacheMap.Remove(node.Value.key);
            node.Value.value.Close();
        }
    }

    class LRUCacheItem<K, V>
    {
        public LRUCacheItem(K k, V v)
        {
            key = k;
            value = v;
        }
        public K key;
        public V value;
    }
}
