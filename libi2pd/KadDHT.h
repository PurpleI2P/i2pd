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
#include "Identity.h"

// Kademlia DHT (XOR distance)

namespace i2p 
{
namespace data 
{
	struct DHTNode
	{
		DHTNode * zero, * one;
		IdentHash * hash;

		DHTNode ();
		~DHTNode (); 

		bool IsEmpty () const { return !zero && !one && !hash; };
		void MoveHashUp (bool fromOne);
	};

	class DHTTable 
	{
		public:

			DHTTable ();
			~DHTTable ();

			DHTNode * Insert (const IdentHash& h);
			bool Remove (const IdentHash& h);
			IdentHash * FindClosest (const IdentHash& h);
			std::vector<IdentHash *> FindClosest (const IdentHash& h, size_t num);
			
			void Print (std::stringstream& s);	
			size_t GetSize () const { return m_Size; };
			
		private:

			DHTNode * Insert (IdentHash * h, DHTNode * root, int level); // recursive
			bool Remove (const IdentHash& h, DHTNode * root, int level);
			IdentHash * FindClosest (const IdentHash& h, DHTNode * root, int level);
			void FindClosest (const IdentHash& h, size_t num, DHTNode * root, int level, std::vector<IdentHash *>& hashes);
			void Print (std::stringstream& s, DHTNode * root, int level);	
			
		private:

			DHTNode * m_Root;
			size_t m_Size;
	};	
}
}

#endif
