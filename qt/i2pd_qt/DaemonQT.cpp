#include <memory>
#include "mainwindow.h"
#include <QApplication>
#include <stdlib.h>
#include "../../Daemon.h"

namespace i2p
{
namespace util
{
	class DaemonQTImpl: public std::enable_shared_from_this<DaemonQTImpl>
	{
		public:

			DaemonQTImpl (int argc, char* argv[]):
				m_App (argc, argv)
			{
			}

			void Run ()
			{
				MainWindow w;
				w.show ();
                m_App.exec();
			}

		private:

			void StartDaemon ()
			{
				Daemon.start ();
			}

			void StopDaemon ()
			{
				Daemon.stop ();
			}	 

            bool IsRunning () const
			{
				return Daemon.running;
			}

		private:

			QApplication m_App;	
	};	

	bool DaemonQT::init(int argc, char* argv[])
	{
        m_Impl = std::make_shared<DaemonQTImpl> (argc, argv);
        return Daemon_Singleton::init(argc, argv);
	}

	void DaemonQT::run ()
	{
		if (m_Impl)
		{
			m_Impl->Run ();
			m_Impl = nullptr;
		}
	}
}
}
