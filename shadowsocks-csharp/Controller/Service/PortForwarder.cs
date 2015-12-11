using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Shadowsocks.Controller
{
    /// <summary>
    /// 端口转发服务
    /// </summary>
    class PortForwarder : Listener.Service
    {
        int _targetPort;

        public PortForwarder(int targetPort)
        {
            this._targetPort = targetPort;
        }

        public bool Handle(byte[] firstPacket, int length, Socket socket, object state)
        {
            if (socket.ProtocolType != ProtocolType.Tcp)
            {
                return false;
            }
            new Handler().Start(firstPacket, length, socket, this._targetPort);
            return true;
        }

        class Handler
        {
            private byte[] _firstPacket;
            private int _firstPacketLength;
            private Socket _local;  //与客户端连接的tcp socket
            private Socket _remote;     // 与转发目标端连接的tcp socket
            private bool _closed = false;
            private bool _localShutdown = false;
            private bool _remoteShutdown = false;
            public const int RecvSize = 16384;
            // remote receive buffer
            private byte[] remoteRecvBuffer = new byte[RecvSize];
            // connection receive buffer
            private byte[] connetionRecvBuffer = new byte[RecvSize];

            public void Start(byte[] firstPacket, int length, Socket socket, int targetPort)
            {
                this._firstPacket = firstPacket;
                this._firstPacketLength = length;
                this._local = socket;
                try
                {
                    // TODO async resolving
                    IPAddress ipAddress;
                    bool parsed = IPAddress.TryParse("127.0.0.1", out ipAddress);
                    IPEndPoint remoteEP = new IPEndPoint(ipAddress, targetPort);


                    _remote = new Socket(ipAddress.AddressFamily,
                        SocketType.Stream, ProtocolType.Tcp);
                    _remote.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);

                    // Connect to the remote endpoint.
                    _remote.BeginConnect(remoteEP,
                        new AsyncCallback(ConnectCallback), null);
                }
                catch (Exception e)
                {
                    Logging.LogUsefulException(e);
                    this.Close();
                }
            }

            /// <summary>
            /// 连接到目标端后的回调方法。 调用HandshakeReceive(), 向目标端转发数据
            /// </summary>
            /// <param name="ar"></param>
            private void ConnectCallback(IAsyncResult ar)
            {
                if (_closed)
                {
                    return;
                }
                try
                {
                    _remote.EndConnect(ar);
                    HandshakeReceive();
                }
                catch (Exception e)
                {
                    Logging.LogUsefulException(e);
                    this.Close();
                }
            }

            /// <summary>
            /// 向目标端转发数据
            /// </summary>
            private void HandshakeReceive()
            {
                if (_closed)
                {
                    return;
                }
                try
                {
                    // 向目标端转发数据
                    _remote.BeginSend(_firstPacket, 0, _firstPacketLength, 0, new AsyncCallback(StartPipe), null);
                }
                catch (Exception e)
                {
                    Logging.LogUsefulException(e);
                    this.Close();
                }
            }

            /// <summary>
            /// 向目标端转发数据后的回调方法。
            /// 开始等待目标端与客户端的数据
            /// </summary>
            /// <param name="ar"></param>
            private void StartPipe(IAsyncResult ar)
            {
                if (_closed)
                {
                    return;
                }
                try
                {
                    _remote.EndSend(ar);
                    // 等待接收目标端数据
                    _remote.BeginReceive(remoteRecvBuffer, 0, RecvSize, 0,
                        new AsyncCallback(PipeRemoteReceiveCallback), null);
                    // 等待接收客户端数据
                    _local.BeginReceive(connetionRecvBuffer, 0, RecvSize, 0,
                        new AsyncCallback(PipeConnectionReceiveCallback), null);
                }
                catch (Exception e)
                {
                    Logging.LogUsefulException(e);
                    this.Close();
                }
            }

            /// <summary>
            /// 从目标端接收到数据后的回调方法。
            /// 回发给客户端。
            /// </summary>
            /// <param name="ar"></param>
            private void PipeRemoteReceiveCallback(IAsyncResult ar)
            {
                if (_closed)
                {
                    return;
                }
                try
                {
                    int bytesRead = _remote.EndReceive(ar);

                    if (bytesRead > 0)
                    {
                        // 回发给客户端
                        _local.BeginSend(remoteRecvBuffer, 0, bytesRead, 0, new AsyncCallback(PipeConnectionSendCallback), null);
                    }
                    else
                    {
                        //Console.WriteLine("bytesRead: " + bytesRead.ToString());
                        _local.Shutdown(SocketShutdown.Send);
                        _localShutdown = true;
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
            /// 从客户端接收到数据后的回调方法。
            /// 转发给目标端。
            /// </summary>
            /// <param name="ar"></param>
            private void PipeConnectionReceiveCallback(IAsyncResult ar)
            {
                if (_closed)
                {
                    return;
                }
                try
                {
                    int bytesRead = _local.EndReceive(ar);

                    if (bytesRead > 0)
                    {
                        // 转发给目标端
                        _remote.BeginSend(connetionRecvBuffer, 0, bytesRead, 0, new AsyncCallback(PipeRemoteSendCallback), null);
                    }
                    else
                    {
                        _remote.Shutdown(SocketShutdown.Send);
                        _remoteShutdown = true;
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
            /// 向目标端转发数据后的回调方法。
            /// 继续等待从客户端接收数据。
            /// </summary>
            /// <param name="ar"></param>
            private void PipeRemoteSendCallback(IAsyncResult ar)
            {
                if (_closed)
                {
                    return;
                }
                try
                {
                    _remote.EndSend(ar);
                    _local.BeginReceive(this.connetionRecvBuffer, 0, RecvSize, 0,
                        new AsyncCallback(PipeConnectionReceiveCallback), null);
                }
                catch (Exception e)
                {
                    Logging.LogUsefulException(e);
                    this.Close();
                }
            }

            /// <summary>
            /// 将响应数据回发给客户端后的回调方法。
            /// 继续等待从目标端接收数据。
            /// </summary>
            /// <param name="ar"></param>
            private void PipeConnectionSendCallback(IAsyncResult ar)
            {
                if (_closed)
                {
                    return;
                }
                try
                {
                    _local.EndSend(ar);
                    _remote.BeginReceive(this.remoteRecvBuffer, 0, RecvSize, 0,
                        new AsyncCallback(PipeRemoteReceiveCallback), null);
                }
                catch (Exception e)
                {
                    Logging.LogUsefulException(e);
                    this.Close();
                }
            }

            private void CheckClose()
            {
                if (_localShutdown && _remoteShutdown)
                {
                    this.Close();
                }
            }

            public void Close()
            {
                lock (this)
                {
                    if (_closed)
                    {
                        return;
                    }
                    _closed = true;
                }
                if (_local != null)
                {
                    try
                    {
                        _local.Shutdown(SocketShutdown.Both);
                        _local.Close();
                    }
                    catch (Exception e)
                    {
                        Logging.LogUsefulException(e);
                    }
                }
                if (_remote != null)
                {
                    try
                    {
                        _remote.Shutdown(SocketShutdown.Both);
                        _remote.Close();
                    }
                    catch (SocketException e)
                    {
                        Logging.LogUsefulException(e);
                    }
                }
            }
        }
    }
}
