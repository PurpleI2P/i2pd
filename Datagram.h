#ifndef DATAGRAM_H__
#define DATAGRAM_H__

#include <inttypes.h>
#include <memory>
#include <functional>
#include <map>
#include "Base.h"
#include "Identity.h"
#include "LeaseSet.h"
#include "I2NPProtocol.h"
#include "Garlic.h"

namespace i2p
{
namespace client
{
	class ClientDestination;
}
namespace datagram
{

  // seconds interval for cleanup timer
  const int DATAGRAM_SESSION_CLEANUP_INTERVAL = 3;
  // milliseconds for max session idle time (10 minutes)
  const uint64_t DATAGRAM_SESSION_MAX_IDLE = 3600 * 1000;

  
  class DatagramSession
  {
  public:
    DatagramSession(i2p::client::ClientDestination * localDestination,
                    const i2p::data::IdentHash & remoteIdent);

    /** send an i2np message to remote endpoint for this session */
    void SendMsg(std::shared_ptr<I2NPMessage> msg);
    /** get the last time in milliseconds for when we used this datagram session */
    uint64_t LastActivity() const { return m_LastUse; }
  private:

    /** get next usable routing path, try reusing outbound tunnels  */
    std::shared_ptr<i2p::garlic::GarlicRoutingPath> GetNextRoutingPath();
    /** 
     *  mark current routing path as invalid and clear it
     *  if the outbound tunnel we were using was okay don't use the IBGW in the routing path's lease next time
     */
    void ResetRoutingPath();

    /** get next usable lease, does not fetch or update if expired or have no lease set */
    std::shared_ptr<const i2p::data::Lease> GetNextLease();
    
    void HandleSend(std::shared_ptr<I2NPMessage> msg);
    void HandleGotLeaseSet(std::shared_ptr<const i2p::data::LeaseSet> remoteIdent,
                           std::shared_ptr<I2NPMessage> msg);
    void UpdateLeaseSet(std::shared_ptr<I2NPMessage> msg=nullptr);
    
  private:
    i2p::client::ClientDestination * m_LocalDestination;
    i2p::data::IdentHash m_RemoteIdentity;
    std::shared_ptr<i2p::garlic::GarlicRoutingSession> m_RoutingSession;
    // Ident hash of IBGW that are invalid
    std::vector<i2p::data::IdentHash> m_InvalidIBGW;
    std::shared_ptr<const i2p::data::LeaseSet> m_RemoteLeaseSet;
    uint64_t m_LastUse;
  };
  
	const size_t MAX_DATAGRAM_SIZE = 32768;  
	class DatagramDestination
	{
		typedef std::function<void (const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)> Receiver;

		public:

			DatagramDestination (std::shared_ptr<i2p::client::ClientDestination> owner);
			~DatagramDestination ();				

			void SendDatagramTo (const uint8_t * payload, size_t len, const i2p::data::IdentHash& ident, uint16_t fromPort = 0, uint16_t toPort = 0);
			void HandleDataMessagePayload (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len);

			void SetReceiver (const Receiver& receiver) { m_Receiver = receiver; };
			void ResetReceiver () { m_Receiver = nullptr; };

			void SetReceiver (const Receiver& receiver, uint16_t port) { m_ReceiversByPorts[port] = receiver; };
			void ResetReceiver (uint16_t port) { m_ReceiversByPorts.erase (port); };
    
		private:
      // clean up after next tick
      void ScheduleCleanup();
    
      // clean up stale sessions and expire tags
      void HandleCleanUp(const boost::system::error_code & ecode);
      
      std::shared_ptr<DatagramSession> ObtainSession(const i2p::data::IdentHash & ident);
			
			std::shared_ptr<I2NPMessage> CreateDataMessage (const uint8_t * payload, size_t len, uint16_t fromPort, uint16_t toPort);

			void HandleDatagram (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len);

		private:
			i2p::client::ClientDestination * m_Owner;
      boost::asio::deadline_timer m_CleanupTimer;
			Receiver m_Receiver; // default
      std::mutex m_SessionsMutex;
      std::map<i2p::data::IdentHash, std::shared_ptr<DatagramSession> > m_Sessions;
			std::map<uint16_t, Receiver> m_ReceiversByPorts;

			i2p::data::GzipInflator m_Inflator;
			i2p::data::GzipDeflator m_Deflator;
	};		
}
}

#endif

