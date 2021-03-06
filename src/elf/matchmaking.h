/*
 * Author: youngtrips
 * Created Time:  Fri 30 Oct 2015 04:41:06 PM CST
 * File Name: matchmaking.h
 * Description: 
 */

#ifndef __MATCHMAKING_H
#define __MATCHMAKING_H

#include <queue>
#include <map>

#include <elf/oid.h>

namespace elf {

typedef std::set<oid_t> TeamSet;

struct MatchEntity;
struct MatchRes;
struct MatchQueue;

class MatchPool {
public:
    enum MatchStatus {
        MATCH_PENDING,  // waitting
        MATCH_DONE,     // matched
        MATCH_DELETED,  // deleted
    };

public:
    ~MatchPool();
    oid_t Push(int elo, int size, oid_t team_id);
    void Del(const oid_t &id);

private:
    MatchPool();
    MatchPool(int type, int team_size, int camp_size);
    void push(MatchEntity *ent);
    bool pop(int size_type);
    bool pop(MatchRes &res);
    MatchEntity *top(int size_type);
    MatchEntity *get_opponent(MatchEntity *ent); 

private:
    int _type;
    int _team_size;
    int _camp_size;
    std::map<int, MatchQueue*> _queues;
    std::map<oid_t, MatchEntity*> _entities;

public:
    static MatchPool *Create(int type, int team_size, int camp_size);
    static MatchPool *Get(int type);
    static void Proc(std::list<MatchRes> &res);
    static void Release();

private:
    static std::map<int, MatchPool*> s_pools; // type ==> pool
};

} // namespace elf

#endif /* !__MATCHMAKING_H */
