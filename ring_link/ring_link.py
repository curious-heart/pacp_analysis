"""
A ring link uses link to simulate ring buffer, its body is as the following:
    ========       ========       ========
    | data |       | data |       | data |
    | idx  |       | idx  |       | idx  |
    --------       --------       --------
    | prev | <--   | prev | <--   | prev |
    | next | -->   | next | -->   | next |
    ========       ========       ========
       |                             |
      / \                            |
       |_____________________________|

'data' is user defined part;
'idx' is the index of "ring buffer". it should be in [0, capacity - 1] (see below "handler"), and loop in this range.
For efficiency, there is a "handler" which contains a dict indexed by 'idx'.
All "idx" of nodes are in ascendant order, and "head" can points to any node.

The "handler", contains "head" and "tail" pointing to head and tail node of above body (they actually point
to two neighbor nodes), "capacity" indicating the maximum nodes the link can contain, "cnt" recording the number of
nodes, "indices" dictionary of {index, node} pair for quick locating node, and a "ctrl_blk" for customizaiton info.

E.g, if "capacity" is 8, indices of nodes in a full link is "0->1->2->3->4->5->6->7", and "head" may be 2 (the "tail"
is 1).
"""
_g_def_round_len = 65536
_g_round_len = _g_def_round_len
def init_ring_link(capacity = _g_def_round_len):
    """
    Input:
        capacity: the capacity of ring link.
    return a handler dict with the following keys:
        capacity: capacity of ring link.
        head, tail: ring link head and tail.
        cnt: current number of items in ring link.
        indices: an dict for quick find node in ring link.
        ctrl_blk: user defined control information. None as init.
    """
    hdlr = dict()
    hdlr['capacity'] = capacity
    hdlr['head'] = hdlr['tail'] = None
    hdlr['cnt'] = 0
    hdlr['indices'] = dict()
    hdlr['ctrl_blk'] = None

    _g_round_len = capacity
    return hdlr

def get_a_new_ring_link_node(idx = 0):
    """
    return an empty node with keys: data, next, prev. data is inited as None, and prev/next points to self.
    """
    node = dict()
    node['data'] = None
    node['idx'] = idx
    node['next'] = node['prev'] = node
    return node

def ring_link_is_empty(handler):
    """
    input the handler that init_a_ring_link returned.
    return True of False to indicate if the ring link is empty.
    """
    return bool(handler['cnt'] == 0)

def ring_link_is_full(handler):
    """
    input the handler that init_a_ring_link returned.
    return True of False to indicate if the ring link is full.
    """
    return bool(handler['cnt'] == handler['capacity'])

def _insert_node_into_ring_link(handler, node, pos = None, where = 'after'):
    """
    Input:
        handler: the ring link to be inserted.
        node: the new node to be inserted.
        pos: the node at where the new node to be inserted. It can be None if the node is to be inserted
            at the head or tail.
        where: can be 'after' or 'before', means after or before pos.
    Return:
        True: insert successfully.
        False: insert fails because ring link is full.
    """
    if ring_link_is_full(handler): return False

    node['next'] = node['prev'] = node

    if ring_link_is_empty(handler):
        handler['head'] = handler['tail'] = node
        handler['cnt'] = 1
        handler['indices'][node['idx']] = node
        return True

    if 'after' == where:
        if None == pos: pos = handler['tail']
        node['next'] = pos['next']
        node['prev'] = pos
        pos['next']['prev'] = node
        pos['next'] = node
        if pos is handler['tail']: handler['tail'] = node
    else:
        if None == pos: pos = handler['head']
        node['prev'] = pos['prev']
        node['next'] = pos
        pos['prev']['next'] = node
        pos['prev'] = node
        if pos is handler['head']: handler['head'] = node

    handler['cnt'] += 1
    handler['indices'][node['idx']] = node
    return True

def del_node_from_ring_link(handler, node):
    """
    Input:
        handler: the ring link handler returned from init_a_ring_link.
        node: the node to be deleted.
        release_node: del the node if True.
    """
    node['prev']['next'] = node['next']
    node['next']['prev'] = node['prev']
    handler['cnt'] -= 1
    if 0 == handler['cnt']:
        handler['head'] = handler['tail'] = None
    else:
        if node is handler['head']: handler['head'] = node['next']
        if node is handler['tail']: handler['tail'] = node['prev']

    node['next'] = node['prev'] = node
    del handler['indices'][node['idx']]

def in_round_range(n, s, e, round_len = _g_round_len, s_inc = False, e_inc = False):
    def lte(a, b, inc): return (a <= b) if inc else a < b
    def gte(a, b, inc): return a >= b if inc else a > b

    return (lte(s, n, s_inc) and lte(n, e, e_inc)) if (s <= e) else \
            ((lte(s, n, s_inc) and lte(n, round_len - 1, True)) or \
            (lte(0, n, True) and lte(n, e, e_inc)))

def count_round_number(s, e, round_len = _g_round_len, e_inc = True):
    extra = 1 if e_inc else 0
    return (e - s + extra) if s <= e else (round_len - s + e + extra)

def round_sub(s, cnt, round_len = _g_round_len):
    """
    return s - cnt, in round mode.
    """
    if s - cnt >= 0: return (s - cnt)
    return (s + (round_len - cnt)) % round_len

def round_add(s, cnt,  round_len = _g_round_len):
    """
    return s + cnt, in round mode.
    """
    return (s + cnt) % round_len

def insert_node_into_ring_link(handler, node, mode = 'skip'):
    """
    Input:
        handler: the ring link handler returned from init_a_ring_link.
        node: node to be inserted. the posiiton is based on its idx.
        mode: indicates the action when idx of node is already in the ring buf:
            'skip': do nothing.
            'replace': replace current node.
    Return:
        'full': not inserted due to full ring link.
        'skipped': not inserted due to 'skip' mode.
        'replaced': not inserted due to 'replace' mode.
        'normal': inserted.
    """
    idx = node['idx']
    if idx in handler['indices'].keys():
        if 'skip' == mode: 
            return 'skipped'
        else: #'replace' == mode
            pos = handler['indices'][idx]['prev']
            del_node_from_ring_link(handler, pos['next'])
            if ring_link_is_empty(handler): pos = None
            _insert_node_into_ring_link(handler, node, pos)
            return 'replaced'

    #this is a new node.
    if ring_link_is_full(handler): return 'full'
    if ring_link_is_empty(handler):
        _insert_node_into_ring_link(handler, node, None)
        return 'normal'

    if in_round_range(node['idx'], handler['head']['idx'], handler['tail']['idx']):
        if handler['head']['idx'] < handler['tail']['idx']:
            s_n = handler['head']
            e_n = handler['tail']
        else:
            r_n = handler['head']
            while r_n['idx'] >= handler['head']['idx']: r_n = r_n['next']
            if node['idx'] >= handler['head']['idx']:
                s_n = handler['head']
                e_n = r_n['prev']
            else:
                s_n = r_n
                e_n = handler['tail']
        tmp = s_n
        while node['idx'] > tmp['idx']: tmp = tmp['next']
        pos = tmp
        where = 'before'
    else:
        len_to_h = count_round_number(node['idx'], handler['head']['idx'], handler['capacity'], False)
        len_to_t = count_round_number(handler['tail']['idx'], node['idx'], handler['capacity'], False)
        if len_to_h < len_to_t:
            pos = handler['head']
            where = 'before'
        else:
            pos = handler['tail']
            where = 'after'

    _insert_node_into_ring_link(handler, node, pos, where)

    return 'normal'
