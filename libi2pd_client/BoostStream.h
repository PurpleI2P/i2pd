/*
* Copyright (c) 2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef BOOST_STREAM_H_
#define BOOST_STREAM_H_

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include "Streaming.h"

namespace i2p
{
namespace client
{
	class BoostAsyncStream // for boost::beast and boost::asio
	{
		public:

			using executor_type = boost::asio::any_io_executor;

			BoostAsyncStream (std::shared_ptr<i2p::stream::Stream> stream): m_Stream (stream) {}

			std::shared_ptr<i2p::stream::Stream> GetStream () const { return m_Stream; }

			// AsyncStream
			executor_type get_executor() noexcept { return m_Stream->GetService ().get_executor(); }

			// AsyncReadStream
			template<typename MutableBufferSequence, typename ReadHandler>
			void async_read_some(const MutableBufferSequence& bufs, ReadHandler&& handler)
			{
				if (m_Stream->GetStatus () == i2p::stream::eStreamStatusClosed ||
					m_Stream->GetStatus () == i2p::stream::eStreamStatusTerminated)
				{
					//  read stream after close, return eof
					handler (boost::asio::error::make_error_code (boost::asio::error::eof), 0);
					return;
				}
				size_t received = 0;
				for (auto it = boost::asio::buffer_sequence_begin (bufs); it != boost::asio::buffer_sequence_end (bufs); it++)
				{
					auto len = m_Stream->ReadSome ((uint8_t *)it->data (), it->size ());
					received += len;
					if (received < it->size ()) break;
				}
				if (received > 0) // we have some data
					handler (boost::system::error_code (), received);
				else if (bufs.size () > 0) // wait for incoming data
					m_Stream->AsyncReceive (*boost::asio::buffer_sequence_begin (bufs), std::move (handler), i2p::stream::MAX_RECEIVE_TIMEOUT);
				else
					handler (boost::system::error_code (), 0);
			}

			// AsyncWriteStream
			template<typename ConstBufferSequence, typename WriteHandler>
			void async_write_some(const ConstBufferSequence& bufs, WriteHandler&& handler)
			{
				std::vector<std::pair<const uint8_t *, size_t> > bufsToSend;
				size_t sent = 0;
				for (auto it = boost::asio::buffer_sequence_begin (bufs); it != boost::asio::buffer_sequence_end (bufs); it++)
				{
					const auto& buf = *it;
					sent += buf.size ();
					bufsToSend.push_back ({ (const uint8_t *)buf.data (), buf.size () });
				}
				if (sent)
				{
#ifdef __cpp_lib_move_only_function // with C++23
					// we can save handler with SendBuffer
					auto sendBuffer = std::make_shared<i2p::stream::SendBuffer>(bufsToSend, sent, std::move (handler));
#else
					// we can't save handler with SendBuffer due to lack of std::move_only_function
					auto sendBuffer = std::make_shared<i2p::stream::SendBuffer>(bufsToSend, sent, nullptr);
#endif
					m_Stream->Send (std::move (sendBuffer));
#ifndef __cpp_lib_move_only_function // no std::move_only_function
					// invoke handler right after send
					handler (boost::system::error_code (), sent);
#endif
				}
				else
					handler (boost::system::error_code (), 0);
			}

		private:

			std::shared_ptr<i2p::stream::Stream> m_Stream;
	};
}
}

namespace boost::beast
{
	// for websockets over BoostAsyncStream
	template<typename TeardownHandler>
	void async_teardown (boost::beast::role_type role, i2p::client::BoostAsyncStream& stream, TeardownHandler&& handler)
	{
		auto s = stream.GetStream ();
		if (s) s->Close ();
		handler (boost::system::error_code ()); // TODO: check stream's status
	}
}
#endif
