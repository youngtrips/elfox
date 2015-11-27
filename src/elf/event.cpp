/*
 * Copyright (C) 2011-2014 Yule Fox. All rights reserved.
 * http://www.yulefox.com/
 */

#include <elf/event.h>
#include <elf/log.h>
#include <elf/memory.h>
#include <map>
#include <set>

namespace elf {
typedef std::map<oid_t, callback_t *> callback_list;
typedef std::map<oid_t, callback_list *> listener_list;
typedef std::map<int, listener_list *> listener_map;

static listener_map s_listeners;

struct event_reg_t {
    int evt;
    callback_t *cb;

    event_reg_t(int e, callback_t *c) :
        evt(e),
        cb(c)
    {
    }
};

struct event_unreg_t {
    oid_t oid;
    oid_t lid;
    int evt;

    event_unreg_t(oid_t o, oid_t l, int e) :
        oid(o),
        lid(l),
        evt(e)
    {
    }
};

static std::list<event_reg_t *> s_regs;
static std::list<event_unreg_t *> s_unregs;

static void regist(int evt, callback_t *cb)
{
    assert(cb);
    callback_list *cl = NULL;
    listener_list *ll = NULL;
    listener_map::iterator itr = s_listeners.find(evt);

    if (itr == s_listeners.end()) {
        ll = E_NEW listener_list;
        s_listeners[evt] = ll;
    } else {
        ll = itr->second;
    }

    listener_list::iterator itr_l = ll->find(cb->oid);
    callback_list::iterator itr_c;

    if (itr_l == ll->end()) {
        cl = E_NEW callback_list;
        (*ll)[cb->oid] = cl;
    } else {
        cl = itr_l->second;
    }
    itr_c = cl->find(cb->lid);
    if (itr_c != cl->end()) {
        LOG_WARN("event", "<%lld><%lld> regist event %d (%d) ALREADY.",
                cb->oid, cb->lid, evt, cb->larg);
    } else {
        (*cl)[cb->lid] = cb;
        LOG_TRACE("event", "<%lld><%lld> regist event %d (%d).",
                cb->oid, cb->lid, evt, cb->larg);
    }
}

static void unregist(oid_t oid, oid_t lid, int evt)
{
    LOG_TRACE("event", "<%lld> <%lld> unregist event %d.",
            oid, lid, evt);
    if (evt > 0) {
        listener_map::iterator itr = s_listeners.find(evt);

        if (itr == s_listeners.end()) {
            LOG_WARN("event", "<%lld> has NO event %d.",
                    oid, evt);
            return;
        }

        listener_list *ll = itr->second;

        assert(ll);
        listener_list::iterator itr_l = ll->find(oid);

        if (itr_l != ll->end()) {
            callback_list *cl = itr_l->second;
            callback_list::iterator itr_c = cl->begin();

            while (itr_c != cl->end()) {
                callback_t *cb = itr_c->second;

                if (lid == OID_NIL || lid == cb->lid) {
                    E_FREE(cb);
                    cl->erase(itr_c++);
                } else {
                    ++itr_c;
                }
            }
            if (cl->empty()) {
                E_DELETE(cl);
                ll->erase(itr_l);
            }
        }
    } else {
        listener_map::iterator itr = s_listeners.begin();

        for (; itr != s_listeners.end(); ++itr) {
            listener_list *ll = itr->second;

            assert(ll);
            listener_list::iterator itr_l = ll->find(oid);

            if (itr_l != ll->end()) {
                callback_list *cl = itr_l->second;
                callback_list::iterator itr_c = cl->begin();

                while (itr_c != cl->end()) {
                    callback_t *cb = itr_c->second;

                    if (lid == OID_NIL || lid == cb->lid) {
                        E_FREE(cb);
                        cl->erase(itr_c++);
                    } else {
                        ++itr_c;
                    }
                }
                if (cl->empty()) {
                    E_DELETE(cl);
                    ll->erase(itr_l);
                }
            }
        }
    }
}

int event_init(void)
{
    MODULE_IMPORT_SWITCH;
    return 0;
}

int event_fini(void)
{
    MODULE_IMPORT_SWITCH;
    return 0;
}

int event_proc(void)
{
    std::list<event_reg_t *>::const_iterator itr_r = s_regs.begin();
    std::list<event_unreg_t *>::const_iterator itr_u = s_unregs.begin();

    for (; itr_u != s_unregs.end(); ++itr_u) {
        event_unreg_t *s = *itr_u;

        unregist(s->oid, s->lid, s->evt);
        E_DELETE(s);
    }

    for (; itr_r != s_regs.end(); ++itr_r) {
        event_reg_t *s = *itr_r;

        regist(s->evt, s->cb);
        E_DELETE(s);
    }

    s_regs.clear();
    s_unregs.clear();
    return 0;
}

void event_regist(int evt, callback_t *cb)
{
    event_reg_t *s = E_NEW event_reg_t(evt, cb);

    s_regs.push_back(s);
}

void event_unregist(oid_t oid, oid_t lid, int evt)
{
    event_unreg_t *s = E_NEW event_unreg_t(oid, lid, evt);

    s_unregs.push_back(s);
}

void event_emit(int evt, int arg_a, int arg_b, oid_t oid)
{
    LOG_TRACE("event", "<%lld> emit event %d:%d(%d).",
            oid, evt, arg_a, arg_b);

    // get event listeners
    listener_map::iterator itr = s_listeners.find(evt);

    if (itr == s_listeners.end()) {
        return;
    }

    // get listener
    listener_list *ll = itr->second;
    listener_list::iterator itr_l = ll->find(oid);

    if (itr_l == ll->end()) {
        return;
    }

    callback_list *cl = itr_l->second;
    callback_list::iterator itr_c = cl->begin();

    for (; itr_c != cl->end(); ++itr_c) {
        callback_t *cb = itr_c->second;

        cb->tid = oid;
        cb->targ_a = arg_a;
        cb->targ_b = arg_b;
        cb->func(cb);
    }
}
} // namespace elf

