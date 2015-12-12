﻿using System.IO;
using Shadowsocks.Model;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Net.Sockets;
using Shadowsocks.Controller.Strategy;
using System.Net;

namespace Shadowsocks.Controller
{
    public class ShadowsocksController
    {
        // controller:
        // handle user actions
        // manipulates UI
        // interacts with low level logic

        private Thread _ramThread;

        private Listener _listener;
        private PACServer _pacServer;
        private Configuration _config;
        private StrategyManager _strategyManager;
        private PolipoRunner polipoRunner;
        private GFWListUpdater gfwListUpdater;
        public AvailabilityStatistics availabilityStatistics { get; private set; }
        public StatisticsStrategyConfiguration StatisticsConfiguration { get; private set; }

        private bool stopped = false;

        private bool _systemProxyIsDirty = false;

        public class PathEventArgs : EventArgs
        {
            public string Path;
        }

        public event EventHandler ConfigChanged;
        public event EventHandler EnableStatusChanged;
        public event EventHandler EnableGlobalChanged;
        public event EventHandler ShareOverLANStatusChanged;

        // when user clicked Edit PAC, and PAC file has already created
        public event EventHandler<PathEventArgs> PACFileReadyToOpen;
        public event EventHandler<PathEventArgs> UserRuleFileReadyToOpen;

        public event EventHandler<GFWListUpdater.ResultEventArgs> UpdatePACFromGFWListCompleted;

        public event ErrorEventHandler UpdatePACFromGFWListError;

        public event ErrorEventHandler Errored;

        public ShadowsocksController()
        {
            _config = Configuration.Load();
            StatisticsConfiguration = StatisticsStrategyConfiguration.Load();
            _strategyManager = new StrategyManager(this);
            StartReleasingMemory();
        }


        public void Start()
        {
            Reload();
        }

        protected void ReportError(Exception e)
        {
            if (Errored != null)
            {
                Errored(this, new ErrorEventArgs(e));
            }
        }

        public Server GetCurrentServer()
        {
            return _config.GetCurrentServer();
        }

        // always return copy
        public Configuration GetConfigurationCopy()
        {
            return Configuration.Load();
        }

        // always return current instance
        public Configuration GetCurrentConfiguration()
        {
            return _config;
        }

        public IList<IStrategy> GetStrategies()
        {
            return _strategyManager.GetStrategies();
        }

        public IStrategy GetCurrentStrategy()
        {
            foreach (var strategy in _strategyManager.GetStrategies())
            {
                if (strategy.ID == this._config.strategy)
                {
                    return strategy;
                }
            }
            return null;
        }

        public Server GetAServer(IStrategyCallerType type, IPEndPoint localIPEndPoint)
        {
            IStrategy strategy = GetCurrentStrategy();
            if (strategy != null)
            {
                return strategy.GetAServer(type, localIPEndPoint);
            }
            if (_config.index < 0)
            {
                _config.index = 0;
            }
            return GetCurrentServer();
        }

        public void SaveServers(List<Server> servers, int localPort)
        {
            _config.configs = servers;
            _config.localPort = localPort;
            Configuration.Save(_config);
        }

        public void SaveStrategyConfigurations(StatisticsStrategyConfiguration configuration)
        {
            StatisticsConfiguration = configuration;
            StatisticsStrategyConfiguration.Save(configuration);
        }

        public bool AddServerBySSURL(string ssURL)
        {
            try
            {
                var server = new Server(ssURL);
                _config.configs.Add(server);
                _config.index = _config.configs.Count - 1;
                SaveConfig(_config);
                return true;
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
                return false;
            }
        }

        public void ToggleEnable(bool enabled)
        {
            _config.enabled = enabled;
            UpdateSystemProxy();
            SaveConfig(_config);
            if (EnableStatusChanged != null)
            {
                EnableStatusChanged(this, new EventArgs());
            }
        }

        public void ToggleGlobal(bool global)
        {
            _config.global = global;
            UpdateSystemProxy();
            SaveConfig(_config);
            if (EnableGlobalChanged != null)
            {
                EnableGlobalChanged(this, new EventArgs());
            }
        }

        public void ToggleShareOverLAN(bool enabled)
        {
            _config.shareOverLan = enabled;
            SaveConfig(_config);
            if (ShareOverLANStatusChanged != null)
            {
                ShareOverLANStatusChanged(this, new EventArgs());
            }
        }

        public void SelectServerIndex(int index)
        {
            _config.index = index;
            _config.strategy = null;
            SaveConfig(_config);
        }

        public void SelectStrategy(string strategyID)
        {
            _config.index = -1;
            _config.strategy = strategyID;
            SaveConfig(_config);
        }

        public void Stop()
        {
            if (stopped)
            {
                return;
            }
            stopped = true;
            if (_listener != null)
            {
                _listener.Stop();
            }
            if (polipoRunner != null)
            {
                polipoRunner.Stop();
            }
            if (_config.enabled)
            {
                SystemProxy.Update(_config, true);
            }
        }

        public void TouchPACFile()
        {
            string pacFilename = _pacServer.TouchPACFile();
            if (PACFileReadyToOpen != null)
            {
                PACFileReadyToOpen(this, new PathEventArgs() { Path = pacFilename });
            }
        }

        public void TouchUserRuleFile()
        {
            string userRuleFilename = _pacServer.TouchUserRuleFile();
            if (UserRuleFileReadyToOpen != null)
            {
                UserRuleFileReadyToOpen(this, new PathEventArgs() { Path = userRuleFilename });
            }
        }

        public string GetQRCodeForCurrentServer()
        {
            Server server = GetCurrentServer();
            return GetQRCode(server);
        }

        public static string GetQRCode(Server server)
        {
            string parts = server.method + ":" + server.password + "@" + server.server + ":" + server.server_port;
            string base64 = System.Convert.ToBase64String(Encoding.UTF8.GetBytes(parts));
            return "ss://" + base64;
        }

        public void UpdatePACFromGFWList()
        {
            if (gfwListUpdater != null)
            {
                gfwListUpdater.UpdatePACFromGFWList(_config);
            }
        }

        public void UpdateStatisticsConfiguration(bool enabled)
        {
            if (availabilityStatistics == null) return;
            availabilityStatistics.UpdateConfiguration(_config, StatisticsConfiguration);
            _config.availabilityStatistics = enabled;
            SaveConfig(_config);
        }

        public void SavePACUrl(string pacUrl)
        {
            _config.pacUrl = pacUrl;
            UpdateSystemProxy();
            SaveConfig(_config);
            if (ConfigChanged != null)
            {
                ConfigChanged(this, new EventArgs());
            }
        }

        public void UseOnlinePAC(bool useOnlinePac)
        {
            _config.useOnlinePac = useOnlinePac;
            UpdateSystemProxy();
            SaveConfig(_config);
            if (ConfigChanged != null)
            {
                ConfigChanged(this, new EventArgs());
            }
        }

        public void ToggleCheckingUpdate(bool enabled)
        {
            _config.autoCheckUpdate = enabled;
            Configuration.Save(_config);
        }

        public void SaveLogViewerConfig(LogViewerConfig newConfig)
        {
            _config.logViewer = newConfig;
            Configuration.Save(_config);
        }

        protected void Reload()
        {
            // some logic in configuration updated the config when saving, we need to read it again
            _config = Configuration.Load();
            StatisticsConfiguration = StatisticsStrategyConfiguration.Load();

            if (polipoRunner == null)
            {
                polipoRunner = new PolipoRunner();
            }
            if (_pacServer == null)
            {
                _pacServer = new PACServer();
                _pacServer.PACFileChanged += pacServer_PACFileChanged;
            }
            _pacServer.UpdateConfiguration(_config);
            if (gfwListUpdater == null)
            {
                gfwListUpdater = new GFWListUpdater();
                gfwListUpdater.UpdateCompleted += pacServer_PACUpdateCompleted;
                gfwListUpdater.Error += pacServer_PACUpdateError;
            }

            if (availabilityStatistics == null)
            {
                availabilityStatistics = new AvailabilityStatistics(_config, StatisticsConfiguration);
            }
            availabilityStatistics.UpdateConfiguration(_config, StatisticsConfiguration);

            if (_listener != null)
            {
                _listener.Stop();
            }
            // don't put polipoRunner.Start() before pacServer.Stop()
            // or bind will fail when switching bind address from 0.0.0.0 to 127.0.0.1
            // though UseShellExecute is set to true now
            // http://stackoverflow.com/questions/10235093/socket-doesnt-close-after-application-exits-if-a-launched-process-is-open
            polipoRunner.Stop();
            try
            {
                var strategy = GetCurrentStrategy();
                if (strategy != null)
                {
                    strategy.ReloadServers();
                }

                polipoRunner.Start(_config);

                TCPRelay tcpRelay = new TCPRelay(this);
                UDPRelay udpRelay = new UDPRelay(this);
                List<Listener.Service> services = new List<Listener.Service>();
                services.Add(tcpRelay); // 开启本地socks5 tcp代理服务
                services.Add(udpRelay); // 开启本地socks5 udp代理服务
                services.Add(_pacServer);   // 开启本地pac服务器

                /*
                   这里是shadowsocks-windows能成为http代理的关键之处。:100:
                   我们在对ss-windows设置各种代理模式时，实际上只是对系统的internet选项进行的http代理设置。
                   我们知道，ss服务器是一个socks协议的代理，为什么对系统的http代理请求也能起作用呢？

                   当ss-windows启动时，同时会启动privoxy.exe(监听8123端口，可配置)，privoxy是一个http代理，它收到http请求后，
                   转化成socks协议的数据，再转发给ss端口，由ss访问internet，再层层向回发。

                             http请求                     转发给                           封包成socks5协议，转发给
                   browser-------------> ss socks5 代理 ----------------------> privoxy -----------------------------> ss socks5 代理
                         <--------------               <----------------------         <-----------------------------
                         转发http响应数据                 封包成http形式数据                 将结果以socks5形式返回 

                */
                services.Add(new PortForwarder(polipoRunner.RunningPort));  //开启本地http代理服务
                _listener = new Listener(services);
                _listener.Start(_config);
            }
            catch (Exception e)
            {
                // translate Microsoft language into human language
                // i.e. An attempt was made to access a socket in a way forbidden by its access permissions => Port already in use
                if (e is SocketException)
                {
                    SocketException se = (SocketException)e;
                    if (se.SocketErrorCode == SocketError.AccessDenied)
                    {
                        e = new Exception(I18N.GetString("Port already in use"), e);
                    }
                }
                Logging.LogUsefulException(e);
                ReportError(e);
            }

            if (ConfigChanged != null)
            {
                ConfigChanged(this, new EventArgs());
            }

            UpdateSystemProxy();
            Util.Utils.ReleaseMemory(true);
        }

        protected void SaveConfig(Configuration newConfig)
        {
            Configuration.Save(newConfig);
            Reload();
        }

        private void UpdateSystemProxy()
        {
            if (_config.enabled)
            {
                SystemProxy.Update(_config, false);
                _systemProxyIsDirty = true;
            }
            else
            {
                // only switch it off if we have switched it on
                if (_systemProxyIsDirty)
                {
                    SystemProxy.Update(_config, false);
                    _systemProxyIsDirty = false;
                }
            }
        }

        private void pacServer_PACFileChanged(object sender, EventArgs e)
        {
            UpdateSystemProxy();
        }

        private void pacServer_PACUpdateCompleted(object sender, GFWListUpdater.ResultEventArgs e)
        {
            if (UpdatePACFromGFWListCompleted != null)
                UpdatePACFromGFWListCompleted(this, e);
        }

        private void pacServer_PACUpdateError(object sender, ErrorEventArgs e)
        {
            if (UpdatePACFromGFWListError != null)
                UpdatePACFromGFWListError(this, e);
        }

        private void StartReleasingMemory()
        {
            _ramThread = new Thread(new ThreadStart(ReleaseMemory));
            _ramThread.IsBackground = true;
            _ramThread.Start();
        }

        private void ReleaseMemory()
        {
            while (true)
            {
                Util.Utils.ReleaseMemory(false);
                Thread.Sleep(30 * 1000);
            }
        }
    }
}
