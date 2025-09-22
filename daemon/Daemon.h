/*
* Copyright (c) 2013-2025, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef DAEMON_H__
#define DAEMON_H__

#include <memory>
#include <string>
#include <string_view>
#include <ostream>
#include <sstream>

namespace i2p
{
namespace util
{
	class Daemon_Singleton_Private;
	class Daemon_Singleton
	{
	public:

		virtual bool init (int argc, char* argv[], std::shared_ptr<std::ostream> logstream);
		virtual bool init (int argc, char* argv[]);
		virtual bool start ();
		virtual bool stop ();
		virtual void run () {};
		
		virtual int GetGracefulShutdownInterval () const { return 0; };
		void setDataDir (std::string_view path);
		
	public:
		
		bool isDaemon;
		bool running;

	protected:

		Daemon_Singleton ();
		virtual ~Daemon_Singleton ();

		bool IsService () const;

		// d-pointer for httpServer, httpProxy, etc.
		class Daemon_Singleton_Private;
		Daemon_Singleton_Private &d;

	private:

		std::string DaemonDataDir;
	};

	void PrintMainWindowText (std::stringstream& s); // for GUI
	
#if defined(QT_GUI_LIB) // check if QT
#define Daemon i2p::util::DaemonQT::Instance()
	// dummy, invoked from RunQT
	class DaemonQT: public i2p::util::Daemon_Singleton
	{
		public:

			static DaemonQT& Instance()
			{
				static DaemonQT instance;
				return instance;
			}
	};

#elif defined(_WIN32)
#define Daemon i2p::util::DaemonWin32::Instance()
	class DaemonWin32 : public Daemon_Singleton
	{
		public:

			static DaemonWin32& Instance()
			{
				static DaemonWin32 instance;
				return instance;
			}
	
			bool init(int argc, char* argv[]);
			bool start();
			bool stop();
			void run ();

			int GetGracefulShutdownInterval () const;

		public:
		
			bool isGraceful;

		private:

			DaemonWin32 (): isGraceful(false) {}
	};
#elif (defined(ANDROID) && !defined(ANDROID_BINARY))
#define Daemon i2p::util::DaemonAndroid::Instance()
	// dummy, invoked from android/jni/DaemonAndroid.*
	class DaemonAndroid: public i2p::util::Daemon_Singleton
	{
		public:

			static DaemonAndroid& Instance()
			{
				static DaemonAndroid instance;
				return instance;
			}
	};
#else // Unix-like systems, including Linux
	class DaemonUnix : public Daemon_Singleton
	{
		public:

			static DaemonUnix& Instance()
			{
				static DaemonUnix instance;
				return instance;
			}

			bool start();
			bool stop();
			void run ();

			int GetGracefulShutdownInterval () const { return gracefulShutdownInterval; };
			
		private:

			std::string pidfile;
			int pidFH;

		public:

			int gracefulShutdownInterval; // in seconds
	};
#if !defined(__HAIKU__)
	#define Daemon i2p::util::DaemonUnix::Instance()
#else
	class DaemonHaiku: public DaemonUnix
	{
		public:
			
			static DaemonHaiku& Instance ()
			{
				static DaemonHaiku instance;
				return instance;
			}	
			
			bool init(int argc, char* argv[]);
			void run ();
	};	
#define Daemon i2p::util::DaemonHaiku::Instance()
#endif
	
#endif
}
}

#endif // DAEMON_H__
