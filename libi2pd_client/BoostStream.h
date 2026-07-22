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
					m_Stream->AsyncReceive (*boost::asio::buffer_sequence_begin (bufs),
						[handler = std::move (handler)](const boost::system::error_code& ecode, size_t bytes_transferred) mutable
						{
							handler (boost::system::error_code (), bytes_transferred);
						});
				else
					handler (boost::system::error_code (), 0);
			}

			// AsyncWriteStream
			template<typename ConstBufferSequence, typename WriteHandler>
			void async_write_some(const ConstBufferSequence& bufs, WriteHandler&& handler)
			{
				size_t sent = 0;
				for (auto it = boost::asio::buffer_sequence_begin (bufs); it != boost::asio::buffer_sequence_end (bufs); it++)
				{
					const auto& buf = *it;
					sent += buf.size ();
					m_Stream->Send ((const uint8_t *)buf.data (), buf.size ());
					// TODO: AsyncSend wiht callback for last buf, but not possible below C++23
				}
				handler (boost::system::error_code (), sent);
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
