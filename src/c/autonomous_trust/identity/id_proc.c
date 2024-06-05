#include <stdarg.h>

#include "processes/processes.h"
#include "structures/map.h"
#include "utilities/message.h"

// FIXME message handlers
int _remember_activity(const process_t *proc, map_t *queues, message_t *msg, int argc, ...)
{
    /*va_list argv;
    char *name = {0};
    //Union[Peers, PeerCapabilities, GroupHistory]

    va_start(argv, argc);
    if (argc > 0)
        name = va_arg(argv, char*);
    if (argc > 1)
        ;
    va_end(argv);*/

    //FIXME update proc->configs with latest data; write to file
    // for name, q in queues.items():
    //        if name != self.name:
    //           q.put(msg, block=True, timeout=self.q_cadence)
    return 0;
}
/*
int _record_group(const process_t *proc, map_t *queues, message_t *msg, int argc, ...)
{
    return remember_activity(proc, queues, msg, 3, "group", group, history);
}

int _record_peers(const process_t *proc, map_t *queues, message_t *msg, int argc, ...)
{
    int err = remember_activity(proc, queues, msg, 2, "peers", peers);
    if (err != 0)
        return err;
    return remember_activity(proc, queues, msg, 2, "capabilities", peer_capabilities);
}
*/

int _acquire_capabilities(const process_t *proc, map_t *queues)
{
    return 0;
}

int _announce_identity(const process_t *proc, map_t *queues)
{
    // FIXME 
    // send network broadcast, no encrypt
    queue_id_t q = fetch_msgq(queues, "network");
    msgq_buf_t buf;  // announcement msg: identity_publish(), package_hash, capabilities_list
    msgsnd(q, &buf, sizeof(message_t), buf.mtype);
    return 0;
}

/*
int choose_group(const process_t *proc, map_t *queues, message_t *msg)
{
    return 0;
}

int receive_history(const process_t *proc, map_t *queues, message_t *msg)
{
    return 0;
}

int count_vote()
{

}

int _vote_collection()
{

}

int _peer_accepted()
{

}

int welcoming_committee()
{
    return false;
}

int _update_group()
{

}

int _add_peer()
{

}

int _process_id()
{

}

int handle_vote_on_peer()
{
    return false;
}

int _vote_response()
{
    return false;
}

int handle_acceptance()
{
    return false;
}

int handle_confirm_peer()
{
    return false;
}

bool handle_history_diff(const process_t *proc, map_t *queues, message_t *msg)
{
    if (proc->phase != 3)
        return false;
}

bool handle_group_update(const process_t *proc, map_t *queues, message_t *msg)
{
    if (proc->phase != 3)
        return false;
}
*/

int identity_run(const process_t *proc, map_t *queues, msgq_key_t signal)
{
    //process_register_handler(proc, "diff", handle_history_diff);
    //process_register_handler(proc, "update", handle_group_update);

    _acquire_capabilities(proc, queues);
    _announce_identity(proc, queues);
    // FIXME chose_group to thread

    return process_run(proc, queues, signal);
}
DECLARE_PROCESS(identity, identity_run);
