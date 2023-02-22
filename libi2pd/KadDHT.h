/*
* Copyright (c) 2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*
*/

#ifndef KADDHT_H__
#define KADDHT_H__

#include <memory>
#include <vector>
#include <sstream>
#include <functional>
#include "RouterInfo.h"

// Kademlia DHT (XOR distance)

namespace i2p 
{
namespace data 
{
	struct DHTNode
	{
		DHTNode * zero, * one;
		std::shared_ptr<RouterInfo> router;

		DHTNode ();
		~DHTNode (); 

		bool IsEmpty () const { return !zero && !one && !router; };
		void MoveRouterUp (bool fromOne);
	};

	class DHTTable 
	{
		typedef std::function<bool (const std::shared_ptr<RouterInfo>&)> Filter;
		public:

			DHTTable ();
			~DHTTable ();

			void Insert (const std::shared_ptr<RouterInfo>& r);
			bool Remove (const IdentHash& h);
			std::shared_ptr<RouterInfo> FindClosest (const IdentHash& h, const Filter& filter = nullptr) const;
			std::vector<std::shared_ptr<RouterInfo> > FindClosest (const IdentHash& h, size_t num, const Filter& filter = nullptr) const;
			
			void Print (std::stringstream& s);	
			size_t GetSize () const { return m_Size; };
			void Clear ();
			void Cleanup (const Filter& filter);
			
		private:

			void Insert (const std::shared_ptr<RouterInfo>& r, DHTNode * root, int level); // recursive
			bool Remove (const IdentHash& h, DHTNode * root, int level);
			std::shared_ptr<RouterInfo> FindClosest (const IdentHash& h, DHTNode * root, int level) const;
			void FindClosest (const IdentHash& h, size_t num, DHTNode * root, int level, std::vector<std::shared_ptr<RouterInfo> >& hashes) const;
			void Cleanup (DHTNode * root);
			void Print (std::stringstream& s, DHTNode * root, int level);	
			
		private:

			DHTNode * m_Root;
			size_t m_Size;
			// transient
			mutable Filter m_Filter;
	};	
}
}

#endif
