#ifndef ENGINE_SHARED_NETBAN_H
#define ENGINE_SHARED_NETBAN_H

#include <base/system.h>


inline int NetComp(const NETADDR *pAddr1, const NETADDR *pAddr2)
{
	return mem_comp(pAddr1, pAddr2, pAddr1->type==NETTYPE_IPV4 ? 8 : 20);
}

class CNetRange
{
public:
	NETADDR m_LB;
	NETADDR m_UB;

	bool IsValid() const { return m_LB.type == m_UB.type && NetComp(&m_LB, &m_UB) < 0; }
};

inline int NetComp(const CNetRange *pRange1, const CNetRange *pRange2)
{
	return NetComp(&pRange1->m_LB, &pRange2->m_LB) || NetComp(&pRange1->m_UB, &pRange2->m_UB);
}


class CNetBan
{
protected:
	bool NetMatch(const NETADDR *pAddr1, const NETADDR *pAddr2) const
	{
		return NetComp(pAddr1, pAddr2) == 0;
	}

	bool NetMatch(const CNetRange *pRange, const NETADDR *pAddr, int Start, int Length) const
	{
		return pRange->m_LB.type == pAddr->type && (Start == 0 || mem_comp(&pRange->m_LB.ip[0], &pAddr->ip[0], Start) == 0) &&
			mem_comp(&pRange->m_LB.ip[Start], &pAddr->ip[Start], Length-Start) <= 0 && mem_comp(&pRange->m_UB.ip[Start], &pAddr->ip[Start], Length-Start) >= 0;
	}

	bool NetMatch(const CNetRange *pRange, const NETADDR *pAddr) const
	{
		return NetMatch(pRange, pAddr, 0,  pRange->m_LB.type==NETTYPE_IPV4 ? 4 : 16);
	}

	const char *NetToString(const NETADDR *pData, char *pBuffer, unsigned BufferSize) const
	{
		char aAddrStr[NETADDR_MAXSTRSIZE];
		net_addr_str(pData, aAddrStr, sizeof(aAddrStr), false);
		str_format(pBuffer, BufferSize, "'%s'", aAddrStr);
		return pBuffer;
	}

	const char *NetToString(const CNetRange *pData, char *pBuffer, unsigned BufferSize) const
	{
		char aAddrStr1[NETADDR_MAXSTRSIZE], aAddrStr2[NETADDR_MAXSTRSIZE];
		net_addr_str(&pData->m_LB, aAddrStr1, sizeof(aAddrStr1), false);
		net_addr_str(&pData->m_UB, aAddrStr2, sizeof(aAddrStr2), false);
		str_format(pBuffer, BufferSize, "'%s' - '%s'", aAddrStr1, aAddrStr2);
		return pBuffer;
	}

	// todo: move?
	static bool StrAllnum(const char *pStr);

	class CNetHash
	{
	public:
		int m_Hash;
		int m_HashIndex;	// matching parts for ranges, 0 for addr

		CNetHash() {}	
		CNetHash(const NETADDR *pAddr);
		CNetHash(const CNetRange *pRange);

		static int MakeHashArray(const NETADDR *pAddr, CNetHash aHash[17]);
	};

	struct CBanInfo
	{
		enum
		{
			EXPIRES_NEVER=-1,
			REASON_LENGTH=64,
		};
		int m_Expires;
		char m_aReason[REASON_LENGTH];
	};

	template<class T> struct CBan
	{
		T m_Data;
		CBanInfo m_Info;
		CNetHash m_NetHash;

		// hash list
		CBan *m_pHashNext;
		CBan *m_pHashPrev;

		// used or free list
		CBan *m_pNext;
		CBan *m_pPrev;
	};

	template<class T, int HashCount> class CBanPool
	{
	public:
		typedef T CDataType;

		CBan<CDataType> *Add(const CDataType *pData, const CBanInfo *pInfo, const CNetHash *pNetHash);
		int Remove(CBan<CDataType> *pBan);
		void Update(CBan<CDataType> *pBan, const CBanInfo *pInfo);
		void Reset();
	
		int Num() const { return m_CountUsed; }
		bool IsFull() const { return m_CountUsed == MAX_BANS; }

		CBan<CDataType> *First() const { return m_pFirstUsed; }
		CBan<CDataType> *First(const CNetHash *pNetHash) const { return m_paaHashList[pNetHash->m_HashIndex][pNetHash->m_Hash]; }
		CBan<CDataType> *Find(const CDataType *pData, const CNetHash *pNetHash) const
		{
			for(CBan<CDataType> *pBan = m_paaHashList[pNetHash->m_HashIndex][pNetHash->m_Hash]; pBan; pBan = pBan->m_pHashNext)
			{
				if(NetComp(&pBan->m_Data, pData) == 0)
					return pBan;
			}

			return 0;
		}
		CBan<CDataType> *Get(int Index) const;

	private:
		enum
		{
			MAX_BANS=1024,
		};

		CBan<CDataType> *m_paaHashList[HashCount][256];
		CBan<CDataType> m_aBans[MAX_BANS];
		CBan<CDataType> *m_pFirstFree;
		CBan<CDataType> *m_pFirstUsed;
		int m_CountUsed;
	};

	typedef CBanPool<NETADDR, 1> CBanAddrPool;
	typedef CBanPool<CNetRange, 16> CBanRangePool;
	typedef CBan<NETADDR> CBanAddr;
	typedef CBan<CNetRange> CBanRange;
	
	template<class T> void MakeBanInfo(const CBan<T> *pBan, char *pBuf, unsigned BuffSize, int Type) const;
	template<class T> int Ban(T *pBanPool, const typename T::CDataType *pData, int Seconds, const char *pReason);
	template<class T> int Unban(T *pBanPool, const typename T::CDataType *pData);

	class IConsole *m_pConsole;
	class IStorage *m_pStorage;
	NETADDR m_LocalhostIPV4, m_LocalhostIPV6;

public:
	enum
	{
		MSGTYPE_PLAYER=0,
		MSGTYPE_LIST,
		MSGTYPE_BANADD,
		MSGTYPE_BANREM,
	};

	CBanAddrPool m_BanAddrPool;
	CBanAddrPool m_PunishAddrPool;
	CBanRangePool m_BanRangePool;
	template<class T> int Punish(T *pBanPool, const typename T::CDataType *pData, int Seconds, const char *pReason);

	class IConsole *Console() const { return m_pConsole; }
	class IStorage *Storage() const { return m_pStorage; }

	virtual ~CNetBan() {}
	void Init(class IConsole *pConsole, class IStorage *pStorage);
	void Update();

	virtual int BanAddr(const NETADDR *pAddr, int Seconds, const char *pReason);
	virtual int BanRange(const CNetRange *pRange, int Seconds, const char *pReason);
	int UnbanByAddr(const NETADDR *pAddr);
	int UnbanByRange(const CNetRange *pRange);
	int UnbanByIndex(int Index);
	void UnbanAll() { m_BanAddrPool.Reset(); m_BanRangePool.Reset(); }
	bool IsBanned(const NETADDR *pAddr, char *pBuf, unsigned BufferSize) const;

	static void ConBan(class IConsole::IResult *pResult, void *pUser);
	static void ConBanRange(class IConsole::IResult *pResult, void *pUser);
	static void ConUnban(class IConsole::IResult *pResult, void *pUser);
	static void ConUnbanRange(class IConsole::IResult *pResult, void *pUser);
	static void ConUnbanAll(class IConsole::IResult *pResult, void *pUser);
	static void ConBans(class IConsole::IResult *pResult, void *pUser);
	static void ConBansSave(class IConsole::IResult *pResult, void *pUser);
};

template<class T, int HashCount>
void CNetBan::CBanPool<T, HashCount>::Update(CBan<CDataType> *pBan, const CBanInfo *pInfo)
{
	pBan->m_Info = *pInfo;

	// remove from used list
	if(pBan->m_pNext)
		pBan->m_pNext->m_pPrev = pBan->m_pPrev;
	if(pBan->m_pPrev)
		pBan->m_pPrev->m_pNext = pBan->m_pNext;
	else
		m_pFirstUsed = pBan->m_pNext;

	// insert it into the used list
	if(m_pFirstUsed)
	{
		for(CBan<T> *p = m_pFirstUsed; ; p = p->m_pNext)
		{
			if(p->m_Info.m_Expires == CBanInfo::EXPIRES_NEVER || (pInfo->m_Expires != CBanInfo::EXPIRES_NEVER && pInfo->m_Expires <= p->m_Info.m_Expires))
			{
				// insert before
				pBan->m_pNext = p;
				pBan->m_pPrev = p->m_pPrev;
				if(p->m_pPrev)
					p->m_pPrev->m_pNext = pBan;
				else
					m_pFirstUsed = pBan;
				p->m_pPrev = pBan;
				break;
			}

			if(!p->m_pNext)
			{
				// last entry
				p->m_pNext = pBan;
				pBan->m_pPrev = p;
				pBan->m_pNext = 0;
				break;
			}
		}
	}
	else
	{
		m_pFirstUsed = pBan;
		pBan->m_pNext = pBan->m_pPrev = 0;
	}
}

template<class T>
int CNetBan::Punish(T *pBanPool, const typename T::CDataType *pData, int Seconds, const char *pReason)
{
	// do not punish localhost
	if(NetMatch(pData, &m_LocalhostIPV4) || NetMatch(pData, &m_LocalhostIPV6))
	{
		Console()->Print(IConsole::OUTPUT_LEVEL_STANDARD, "net_ban", "ban failed (localhost)");
		return -1;
	}

	int Stamp = time_timestamp() + Seconds;

	// set up info
	CBanInfo Info = {0};
	Info.m_Expires = Stamp;
	str_copy(Info.m_aReason, pReason, sizeof(Info.m_aReason));

	// check if it already exists
	CNetHash NetHash(pData);
	CBan<typename T::CDataType> *pBan = pBanPool->Find(pData, &NetHash);
	if(pBan)
	{
		Info.m_Expires += Seconds;

		if(Info.m_Expires > time_timestamp() + 300)
		{ // make it a real ban
		}
		else
		{
			// adjust the punishment
			pBanPool->Update(pBan, &Info);
			char aBuf[128];
			MakeBanInfo(pBan, aBuf, sizeof(aBuf), MSGTYPE_LIST);
			Console()->Print(IConsole::OUTPUT_LEVEL_STANDARD, "net_ban", aBuf);
		}
		return 1;
	}

	// add ban and print result
	pBan = pBanPool->Add(pData, &Info, &NetHash);
	if(pBan)
	{
		char aBuf[128];
		MakeBanInfo(pBan, aBuf, sizeof(aBuf), MSGTYPE_BANADD);
		Console()->Print(IConsole::OUTPUT_LEVEL_STANDARD, "net_ban", aBuf);
		return 0;
	}
	else
		Console()->Print(IConsole::OUTPUT_LEVEL_STANDARD, "net_ban", "ban failed (full banlist)");
	return -1;
}

template<class T>
void CNetBan::MakeBanInfo(const CBan<T> *pBan, char *pBuf, unsigned BuffSize, int Type) const
{
	if(pBan == 0 || pBuf == 0)
	{
		if(BuffSize > 0)
			pBuf[0] = 0;
		return;
	}
	
	// build type based part
	char aBuf[256];
	if(Type == MSGTYPE_PLAYER)
		str_copy(aBuf, "You have been banned", sizeof(aBuf));
	else
	{
		char aTemp[256];
		switch(Type)
		{
		case MSGTYPE_LIST:
			str_format(aBuf, sizeof(aBuf), "%s banned", NetToString(&pBan->m_Data, aTemp, sizeof(aTemp))); break;
		case MSGTYPE_BANADD:
			str_format(aBuf, sizeof(aBuf), "banned %s", NetToString(&pBan->m_Data, aTemp, sizeof(aTemp))); break;
		case MSGTYPE_BANREM:
			str_format(aBuf, sizeof(aBuf), "unbanned %s", NetToString(&pBan->m_Data, aTemp, sizeof(aTemp))); break;
		default:
			aBuf[0] = 0;
		}
	}

	// add info part
	if(pBan->m_Info.m_Expires != CBanInfo::EXPIRES_NEVER)
	{
		int Mins = ((pBan->m_Info.m_Expires-time_timestamp()) + 59) / 60;
		if(Mins <= 1)
			str_format(pBuf, BuffSize, "%s for 1 minute (%s)", aBuf, pBan->m_Info.m_aReason);
		else
			str_format(pBuf, BuffSize, "%s for %d minutes (%s)", aBuf, Mins, pBan->m_Info.m_aReason);
	}
	else
		str_format(pBuf, BuffSize, "%s for life (%s)", aBuf, pBan->m_Info.m_aReason);
}

#endif
