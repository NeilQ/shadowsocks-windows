using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Sockets;
using System.Net;
using Shadowsocks.Encryption;
using Shadowsocks.Model;
using Shadowsocks.Controller.Strategy;
using System.Timers;

namespace Shadowsocks.Controller
{

    /// <summary>
    /// tcp转发服务,实现本地与ss服务器的tcp数据隧道逻辑
    /// </summary>
    class TCPRelay : Listener.Service
    {
        private ShadowsocksController _controller;
        private DateTime _lastSweepTime;

        public ISet<Handler> Handlers
        {
            get; set;
        }

        public TCPRelay(ShadowsocksController controller)
        {
            this._controller = controller;
            this.Handlers = new HashSet<Handler>();
            this._lastSweepTime = DateTime.Now;
        }

        public bool Handle(byte[] firstPacket, int length, Socket socket, object state)
        {
            if (socket.ProtocolType != ProtocolType.Tcp)
            {
                return false;
            }
            /*
             建立与 SOCKS5 服务器的TCP连接后,客户端需要先发送请求来协商版本及认证方式。
                   +----+----------+----------+
                   |VER | NMETHODS | METHODS  |
                   +----+----------+----------+
                   | 1  |    1     | 1 to 255 |
                   +----+----------+----------+
             VER 是 SOCKS 版本，这里应该是 0x05；
             NMETHODS 是 METHODS 部分的长度；
             METHODS 是客户端支持的认证方式列表，每个方法占1字节。当前的定义是：
               0x00 不需要认证
               0x01 GSSAPI
               0x02 用户名、密码认证
               0x03 - 0x7F 由IANA分配(保留)
               0x80 - 0xFE 为私人方法保留
               0xFF 无可接受的方法
            */
            if (length < 2 || firstPacket[0] != 5)
            {
                return false;
            }
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);

            // 此处没有对Handler设置构造器, 分别对connection,controller,relay赋值, 可读性不如UDPRelay的处理
            // :-1:
            // 看了下python版本的代码，其对TcpRelayHandler也用了构造器，为什么这里没有？
            // 作者：怪我咯？
            Handler handler = new Handler();
            handler.connection = socket;
            handler.controller = _controller;
            handler.relay = this;

            handler.Start(firstPacket, length);
            IList<Handler> handlersToClose = new List<Handler>(); // 用于缓存长时间不活动的tcp处理对象，并将其清理
            lock (this.Handlers)
            {
                this.Handlers.Add(handler);
                Logging.Debug($"connections: {Handlers.Count}");
                DateTime now = DateTime.Now;
                // 每超过1秒清理一下长时间不活动的tcp连接
                if (now - _lastSweepTime > TimeSpan.FromSeconds(1))
                {
                    _lastSweepTime = now;
                    foreach (Handler handler1 in this.Handlers)
                    {
                        if (now - handler1.lastActivity > TimeSpan.FromSeconds(900))
                        {
                            handlersToClose.Add(handler1);
                        }
                    }
                }
            }
            foreach (Handler handler1 in handlersToClose)
            {
                Logging.Debug("Closing timed out connection");
                handler1.Close();
            }
            return true;
        }
    }

    class Handler
    {
        //public Encryptor encryptor;
        public IEncryptor encryptor;
        public Server server; // ss服务器信息
        // Client  socket.
        public Socket remote;   // 与ss服务器连接的tcp socket
        public Socket connection;  // 与客户端本地连接的tcp socket
        public ShadowsocksController controller;
        public TCPRelay relay;  // 开启这个处理器的tcp socket转发器 

        public DateTime lastActivity;  // 最后tcp活动时间

        private int retryCount = 0;     // 记录重试连接ss服务器的次数
        private bool connected;     // 标识是否已与ss服务器连接上

        private byte command;
        private byte[] _firstPacket;    //一手数据包
        private int _firstPacketLength;
        // Size of receive buffer.
        public const int RecvSize = 8192;
        public const int RecvReserveSize = IVEncryptor.ONETIMEAUTH_BYTES + IVEncryptor.AUTH_BYTES; // reserve for one-time auth
        public const int BufferSize = RecvSize + RecvReserveSize + 32;

        // ss服务器流量统计字段
        private int totalRead = 0;
        private int totalWrite = 0;

        // 交互过程中的各种数据包容器
        // remote receive buffer
        private byte[] remoteRecvBuffer = new byte[BufferSize];
        // remote send buffer
        private byte[] remoteSendBuffer = new byte[BufferSize];
        // connection receive buffer
        private byte[] connetionRecvBuffer = new byte[BufferSize];
        // connection send buffer
        private byte[] connetionSendBuffer = new byte[BufferSize];
        // Received data string.

        private bool connectionShutdown = false;
        private bool remoteShutdown = false;
        private bool closed = false;

        private object encryptionLock = new object();
        private object decryptionLock = new object();

        private DateTime _startConnectTime;

        /// <summary>
        /// 选择可用的ss服务器
        /// </summary>
        public void CreateRemote()
        {
            Server server = controller.GetAServer(IStrategyCallerType.TCP, (IPEndPoint)connection.RemoteEndPoint);
            if (server == null || server.server == "")
            {
                throw new ArgumentException("No server configured");
            }
            this.encryptor = EncryptorFactory.GetEncryptor(server.method, server.password, server.auth, false);
            this.server = server;
        }

        public void Start(byte[] firstPacket, int length)
        {
            this._firstPacket = firstPacket;
            this._firstPacketLength = length;
            this.HandshakeReceive();
            this.lastActivity = DateTime.Now;
        }

        /// <summary>
        /// 检查客户端socket与远程socket是否断开连接，假如都关闭，则释放相关资源
        /// </summary>
        private void CheckClose()
        {
            if (connectionShutdown && remoteShutdown)
            {
                this.Close();
            }
        }

        /// <summary>
        /// 释放相关资源
        /// </summary>
        public void Close()
        {
            lock (relay.Handlers)
            {
                Logging.Debug($"connections: {relay.Handlers.Count}");
                relay.Handlers.Remove(this);
            }
            lock (this)
            {
                if (closed)
                {
                    return;
                }
                closed = true;
            }
            if (connection != null)
            {
                try
                {
                    connection.Shutdown(SocketShutdown.Both);
                    connection.Close();
                }
                catch (Exception e)
                {
                    Logging.LogUsefulException(e);
                }
            }
            if (remote != null)
            {
                try
                {
                    remote.Shutdown(SocketShutdown.Both);
                    remote.Close();
                }
                catch (Exception e)
                {
                    Logging.LogUsefulException(e);
                }
            }
            lock (encryptionLock)
            {
                lock (decryptionLock)
                {
                    if (encryptor != null)
                    {
                        ((IDisposable)encryptor).Dispose();
                    }
                }
            }
        }

        /// <summary>
        /// 接收客户端发送的数据，进行socks5版本及认证方式的协商。然后向客户端应答
        /// </summary>
        private void HandshakeReceive()
        {
            if (closed)
            {
                return;
            }
            try
            {
                /*
                建立与 SOCKS5 服务器的TCP连接后,客户端需要先发送请求来协商版本及认证方式。
                      +----+----------+----------+
                      |VER | NMETHODS | METHODS  |
                      +----+----------+----------+
                      | 1  |    1     | 1 to 255 |
                      +----+----------+----------+
                VER 是 SOCKS 版本，这里应该是 0x05；
                NMETHODS 是 METHODS 部分的长度；
                METHODS 是客户端支持的认证方式列表，每个方法占1字节。当前的定义是：
                  0x00 不需要认证
                  0x01 GSSAPI
                  0x02 用户名、密码认证
                  0x03 - 0x7F 由IANA分配(保留)
                  0x80 - 0xFE 为私人方法保留
                  0xFF 无可接受的方法
                */
                int bytesRead = _firstPacketLength;

                /*
                   应答数据包，与客户端协商版本与认证方式
                   +----+--------+
                   |VER | METHOD |
                   +----+--------+
                   | 1  |   1    |
                   +----+--------+
                   VER 是 SOCKS 版本，这里应该是 0x05；
                   METHOD 是服务端选中的方法。如果返回 0xFF 表示没有一个认证方法被选中，客户端需要关闭连接。
                */
                if (bytesRead > 1)
                {
                    byte[] response = { 5, 0 }; // 表示不需要认证
                    if (_firstPacket[0] != 5)
                    {
                        // reject socks 4
                        response = new byte[] { 0, 91 }; //91，请求被拒绝或失败,socket4的应答方式，详见 https://zh.wikipedia.org/wiki/SOCKS
                        Console.WriteLine("socks 5 protocol error");
                    }
                    // 向客户端应答
                    Logging.Debug($"======Send Local Port, size:" + response.Length);
                    connection.BeginSend(response, 0, response.Length, 0, new AsyncCallback(HandshakeSendCallback), null);
                }
                else
                {
                    this.Close();
                }
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
                this.Close();
            }
        }

        /// <summary>
        /// 向客户端发送版本协商与认证应答后的回调方法。然后开始接受客户端请求数据
        /// </summary>
        /// <param name="ar"></param>
        private void HandshakeSendCallback(IAsyncResult ar)
        {
            if (closed)
            {
                return;
            }
            try
            {
                connection.EndSend(ar);

                // +----+-----+-------+------+----------+----------+
                // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
                // +----+-----+-------+------+----------+----------+
                // | 1  |  1  | X'00' |  1   | Variable |    2     |
                // +----+-----+-------+------+----------+----------+
                // Skip first 3 bytes
                // :-1: no,no,no.这里是只取头三个字节，“skip first 3 bytes”意为"跳过前三个字节"、“忽略前三个字节”,与代码表达的意思不符
                // "Retrive the top 3 bytes" 更恰当
                /*
                VER 是 SOCKS 版本，这里应该是 0x05；
                CMD 是SOCK的命令码
                    0x01 表示CONNECT请求
                    0x02 表示BIND请求
                    0x03 表示 UDP 转发
                RSV 0x00，保留
                ATYP DST ADDR 类型
                    0x01 IPv4地址，DST ADDR 部分4字节长度
                    0x03 域名，DST ADDR 部分第一个字节为域名长度，DST ADDR 剩余的内容为域名，没有 \0 结尾。
                    0x04 IPv6地址，16个字节长度。
                DST ADDR 目的地址
                DST PROT 网络字节序表示的目的端口
                */
                // TODO validate
                Logging.Debug($"======Receive Local Port, size:" + 3);
                // 等待从客户端接收请求数据,并只取前三个字节
                connection.BeginReceive(connetionRecvBuffer, 0, 3, 0,
                    new AsyncCallback(handshakeReceive2Callback), null);
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
                this.Close();
            }
        }

        /// <summary>
        /// 收到客户端请求数据后的回调方法。
        /// </summary>
        /// <param name="ar"></param>
        private void handshakeReceive2Callback(IAsyncResult ar)
        {
            if (closed)
            {
                return;
            }
            try
            {
                int bytesRead = connection.EndReceive(ar);

                /*
                收到的数据如下: 前三个字节已被截取
                +----+-----+-------+
                |VER | CMD |  RSV  |
                +----+-----+-------+
                | 1  |  1  | X'00' |
                +----+-----+-------+
                */
                if (bytesRead >= 3)
                {
                    /*
                       响应格式如下：
                       +----+-----+-------+------+----------+----------+
                       |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
                       +----+-----+-------+------+----------+----------+
                       | 1  |  1  | X'00' |  1   | Variable |    2     |
                       +----+-----+-------+------+----------+----------+

                    VER 是 SOCKS 版本，这里应该是 0x05；
                    REP 应答字段
                        0x00 表示成功
                        0x01 普通SOCKS服务器连接失败
                        0x02 现有规则不允许连接
                        0x03 网络不可达
                        0x04 主机不可达
                        0x05 连接被拒
                        0x06 TTL 超时
                        0x07 不支持的命令
                        0x08 不支持的地址类型
                        0x09 - 0xFF 未定义
                    RSV 0x00，保留
                    ATYP BND ADDR 类型
                        0x01 IPv4地址，DST ADDR 部分4字节长度
                        0x03 域名，DST ADDR 部分第一个字节为域名长度，DST ADDR 剩余的内容为域名，没有 \0 结尾。
                        0x04 IPv6地址，16个字节长度。
                    BND ADDR 服务器绑定的地址
                    BND PROT 网络字节序表示的服务器绑定的端口

                    */
                    command = connetionRecvBuffer[1];
                    if (command == 1)
                    {
                        byte[] response = { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 }; // 表示请求成功
                        Logging.Debug($"======Send Local Port, size:" + response.Length);
                        // 发送请求应答
                        connection.BeginSend(response, 0, response.Length, 0, new AsyncCallback(ResponseCallback), null);
                    }
                    else if (command == 3)
                    {
                        //数据为 UDP 转发 
                        HandleUDPAssociate();
                    }
                }
                else
                {
                    Console.WriteLine("failed to recv data in handshakeReceive2Callback");
                    this.Close();
                }
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
                this.Close();
            }
        }

        /// <summary>
        /// udp转发处理。也叫udp中继，udp穿透。
        /// 从代码上看，这里并没有实现udp转发，只是欺骗客户端。
        /// </summary>
        private void HandleUDPAssociate()
        {
            /*
            +----+-----+-------+------+----------+----------+
            |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  | X'00' |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+
            */
            // 本地服务器的ip 端口
            IPEndPoint endPoint = (IPEndPoint)connection.LocalEndPoint;
            byte[] address = endPoint.Address.GetAddressBytes();
            int port = endPoint.Port;
            byte[] response = new byte[4 + address.Length + 2];
            //VER
            response[0] = 5;
            // ATYP
            if (endPoint.AddressFamily == AddressFamily.InterNetwork)
            {
                response[3] = 1;
            }
            else if (endPoint.AddressFamily == AddressFamily.InterNetworkV6)
            {
                response[3] = 4;
            }
            // BND.ADDR
            address.CopyTo(response, 4);
            // BND.PORT
            response[response.Length - 1] = (byte)(port & 0xFF);
            response[response.Length - 2] = (byte)((port >> 8) & 0xFF);
            // 向客户端应答，表示建立起连接
            Logging.Debug($"======Send Local Port, size:" + response.Length);
            connection.BeginSend(response, 0, response.Length, 0, new AsyncCallback(ReadAll), true);
        }

        private void ReadAll(IAsyncResult ar)
        {
            if (closed)
            {
                return;
            }
            try
            {
                if (ar.AsyncState != null)
                {
                    connection.EndSend(ar);
                    Logging.Debug($"======Receive Local Port, size:" + RecvSize);
                    connection.BeginReceive(connetionRecvBuffer, 0, RecvSize, 0,
                        new AsyncCallback(ReadAll), null);
                }
                else
                {
                    int bytesRead = connection.EndReceive(ar);
                    if (bytesRead > 0)
                    {
                        Logging.Debug($"======Receive Local Port, size:" + RecvSize);
                        connection.BeginReceive(connetionRecvBuffer, 0, RecvSize, 0,
                            new AsyncCallback(ReadAll), null);
                    }
                    else
                    {
                        this.Close();
                    }
                }
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
                this.Close();
            }
        }

        /// <summary>
        /// 接收客户端转发数据后的回调方法，对客户端请求进行应答
        /// </summary>
        /// <param name="ar"></param>
        private void ResponseCallback(IAsyncResult ar)
        {
            try
            {
                connection.EndSend(ar);

                // 启动代理功能
                StartConnect();
            }

            catch (Exception e)
            {
                Logging.LogUsefulException(e);
                this.Close();
            }
        }

        private class ServerTimer : Timer
        {
            public Server Server;

            public ServerTimer(int p) : base(p)
            {
            }
        }

        /// <summary>
        /// 
        /// </summary>
        private void StartConnect()
        {
            try
            {
                // 选择可用的ss服务器
                CreateRemote();

                // TODO async resolving
                // ss服务器dns解析
                IPAddress ipAddress;
                bool parsed = IPAddress.TryParse(server.server, out ipAddress);
                if (!parsed)
                {
                    IPHostEntry ipHostInfo = Dns.GetHostEntry(server.server);
                    ipAddress = ipHostInfo.AddressList[0];
                }
                IPEndPoint remoteEP = new IPEndPoint(ipAddress, server.server_port);

                // 创建与ss服务器连接的socket
                remote = new Socket(ipAddress.AddressFamily,
                    SocketType.Stream, ProtocolType.Tcp);
                remote.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);

                _startConnectTime = DateTime.Now;
                // 计时器，每过3秒检查与ss服务器的连接状态, 未连接上则重试
                ServerTimer connectTimer = new ServerTimer(3000);
                connectTimer.AutoReset = false;
                connectTimer.Elapsed += connectTimer_Elapsed;
                connectTimer.Enabled = true;
                connectTimer.Server = server;

                connected = false;
                // Connect to the remote endpoint.
                Logging.Debug($"++++++Connect Server Port");
                // 与ss服务器连接
                remote.BeginConnect(remoteEP,
                    new AsyncCallback(ConnectCallback), connectTimer);
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
                this.Close();
            }
        }

        private void connectTimer_Elapsed(object sender, ElapsedEventArgs e)
        {
            if (connected)
            {
                return;
            }
            Server server = ((ServerTimer)sender).Server;
            IStrategy strategy = controller.GetCurrentStrategy();
            if (strategy != null)
            {
                strategy.SetFailure(server);
            }
            Console.WriteLine(String.Format("{0} timed out", server.FriendlyName()));
            remote.Close();
            RetryConnect();
        }

        /// <summary>
        /// 重试与ss服务器连接
        /// </summary>
        private void RetryConnect()
        {
            if (retryCount < 4)
            {
                Logging.Debug("Connection failed, retrying");
                StartConnect();
                retryCount++;
            }
            else
            {
                this.Close();
            }
        }

        /// <summary>
        /// 与ss服务器连接后的回调方法
        /// </summary>
        /// <param name="ar"></param>
        private void ConnectCallback(IAsyncResult ar)
        {
            Server server = null;
            if (closed)
            {
                return;
            }
            try
            {
                // 关闭用于检查连接状态的定时器
                ServerTimer timer = (ServerTimer)ar.AsyncState;
                server = timer.Server;
                timer.Elapsed -= connectTimer_Elapsed;
                timer.Enabled = false;
                timer.Dispose();

                // Complete the connection.
                remote.EndConnect(ar);

                connected = true;

                //Console.WriteLine("Socket connected to {0}",
                //    remote.RemoteEndPoint.ToString());

                var latency = DateTime.Now - _startConnectTime;
                IStrategy strategy = controller.GetCurrentStrategy();
                if (strategy != null)
                {
                    strategy.UpdateLatency(server, latency);
                }

                // 启动ss隧道
                StartPipe();
            }
            catch (ArgumentException)
            {
            }
            catch (Exception e)
            {
                if (server != null)
                {
                    IStrategy strategy = controller.GetCurrentStrategy();
                    if (strategy != null)
                    {
                        strategy.SetFailure(server);
                    }
                }
                Logging.LogUsefulException(e);
                RetryConnect();
            }
        }

        /// <summary>
        /// 启动ss隧道
        /// </summary>
        private void StartPipe()
        {
            if (closed)
            {
                return;
            }
            try
            {
                Logging.Debug($"++++++Receive Server Port, size:" + RecvSize);
                // 等待从ss服务器接收数据
                remote.BeginReceive(remoteRecvBuffer, 0, RecvSize, 0,
                    new AsyncCallback(PipeRemoteReceiveCallback), null);

                // 等待从客户端接收数据 (假如前面握手协商没有成功，则不会到达这里)
                Logging.Debug($"======Receive Local Port, size:" + RecvSize);
                connection.BeginReceive(connetionRecvBuffer, 0, RecvSize, 0,
                    new AsyncCallback(PipeConnectionReceiveCallback), null);
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
                this.Close();
            }
        }

        /// <summary>
        /// 从ss服务器接收到数据后的回调方法。解密并发回给客户端
        /// </summary>
        /// <param name="ar"></param>
        private void PipeRemoteReceiveCallback(IAsyncResult ar)
        {
            if (closed)
            {
                return;
            }
            try
            {
                int bytesRead = remote.EndReceive(ar);
                totalRead += bytesRead;

                if (bytesRead > 0)
                {
                    // 更新ss服务器最后活动时间
                    this.lastActivity = DateTime.Now;
                    // 解密
                    /*
                    +----------+
                    | Payload  |
                    +----------+
                    | Variable |
                    +----------+
                    */
                    int bytesToSend;
                    lock (decryptionLock)
                    {
                        if (closed)
                        {
                            return;
                        }
                        encryptor.Decrypt(remoteRecvBuffer, bytesRead, remoteSendBuffer, out bytesToSend);
                    }
                    // 发回给客户端
                    Logging.Debug($"======Send Local Port, size:" + bytesToSend);
                    connection.BeginSend(remoteSendBuffer, 0, bytesToSend, 0, new AsyncCallback(PipeConnectionSendCallback), null);

                    IStrategy strategy = controller.GetCurrentStrategy();
                    if (strategy != null)
                    {
                        strategy.UpdateLastRead(this.server);
                    }
                }
                else
                {
                    //Console.WriteLine("bytesRead: " + bytesRead.ToString());
                    connection.Shutdown(SocketShutdown.Send);
                    connectionShutdown = true;
                    CheckClose();

                    if (totalRead == 0)
                    {
                        // closed before anything received, reports as failure
                        // disable this feature
                        // controller.GetCurrentStrategy().SetFailure(this.server);
                    }
                }
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
                this.Close();
            }
        }

        /// <summary>
        /// 接收到客户端tcp数据后的回调方法。加密并转发给ss服务器
        /// </summary>
        /// <param name="ar"></param>
        private void PipeConnectionReceiveCallback(IAsyncResult ar)
        {
            if (closed)
            {
                return;
            }
            try
            {
                int bytesRead = connection.EndReceive(ar);
                totalWrite += bytesRead;

                if (bytesRead > 0)
                {
                    // 加密
                    /*
                    +-------+----------+
                    |  IV   | Payload  |
                    +-------+----------+
                    | Fixed | Variable |
                    +-------+----------+
                     */
                    int bytesToSend;
                    lock (encryptionLock)
                    {
                        if (closed)
                        {
                            return;
                        }
                        encryptor.Encrypt(connetionRecvBuffer, bytesRead, connetionSendBuffer, out bytesToSend);
                    }
                    // 转发给ss服务器
                    Logging.Debug($"++++++Send Server Port, size:" + bytesToSend);
                    remote.BeginSend(connetionSendBuffer, 0, bytesToSend, 0, new AsyncCallback(PipeRemoteSendCallback), null);

                    IStrategy strategy = controller.GetCurrentStrategy();
                    if (strategy != null)
                    {
                        strategy.UpdateLastWrite(this.server);
                    }
                }
                else
                {
                    remote.Shutdown(SocketShutdown.Send);
                    remoteShutdown = true;
                    CheckClose();
                }
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
                this.Close();
            }
        }

        /// <summary>
        /// 向ss服务器发送加密数据后的回调方法。客户端socket继续等待从客户端接收数据
        /// </summary>
        /// <param name="ar"></param>
        private void PipeRemoteSendCallback(IAsyncResult ar)
        {
            if (closed)
            {
                return;
            }
            try
            {
                remote.EndSend(ar);
                // 继续等待从客户端接收数据
                Logging.Debug($"======Receive Local Port, size:" + RecvSize);
                connection.BeginReceive(this.connetionRecvBuffer, 0, RecvSize, 0,
                    new AsyncCallback(PipeConnectionReceiveCallback), null);
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
                this.Close();
            }
        }

        /// <summary>
        /// 将转发响应数据发回给客户端后的回调方法。远程socket继续等待从ss服务器接收数据
        /// </summary>
        /// <param name="ar"></param>
        private void PipeConnectionSendCallback(IAsyncResult ar)
        {
            if (closed)
            {
                return;
            }
            try
            {
                connection.EndSend(ar);
                // 继续等待从ss服务器接收数据
                Logging.Debug($"++++++Receive Server Port, size:" + RecvSize);
                remote.BeginReceive(this.remoteRecvBuffer, 0, RecvSize, 0,
                    new AsyncCallback(PipeRemoteReceiveCallback), null);
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
                this.Close();
            }
        }
    }
}
