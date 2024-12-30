import pyshark
import datetime
from datetime import timedelta
import sys
import os
import argparse
from ring_link.ring_link import *

g_version = '2.05.00'
g_app_name = os.path.basename(__file__).split('.')[0]

"""
assumption: sniff time is in ascendant order.
"""

g_pacp_file_opt_key = 'pacp_file'
g_output_file_opt_key = 'output_file'
g_pkt_info_file_opt_key = 'pkt_info_file'
g_dup_pkt_rec_file_opt_key = 'dup_pkt_file'
g_discarded_pkt_rec_file_opt_key = 'discarded_pkt_file'

g_def_output_file_name = "data_groups.txt" 
g_def_pkt_info_file_name = "pkt_info_file.txt"
g_def_dup_pkt_rec_file_name = "duplicate_pkts.txt"
g_def_discarded_pkt_rec_file_name = "discarded_pkts.txt"

g_pkt_timeout_ms_key = 'pkt_timeout_ms'
g_dg_timeout_ms_key = 'dg_timeout_ms'
g_def_pkt_timeout_ms = 500.0 #500ms
g_def_dg_timeout_ms = 500.0 #500ms

g_max_ts_key = 'max_ts_key'
g_def_max_ts = 65535

g_expect_start_ts_key = 'start_ts'
g_def_expect_start_ts = -1 #0

g_flush_cnt_key = 'flush_cnt'
g_def_flush_cnt = 100 * 15

g_expand_output_log_dgs_key = 'expand_lost_dgs'

parser = argparse.ArgumentParser(prog = g_app_name)
parser.add_argument(g_pacp_file_opt_key, default = "", help = "pacp file name")
parser.add_argument('-o', '--' + g_output_file_opt_key, default = g_def_output_file_name, 
        help = "output file name. default as {}".format(g_def_output_file_name))
parser.add_argument('-p', '--' + g_pkt_info_file_opt_key, default = "", 
        help = "file name to rec pkt info. if not assigned, pkt info is not recorded.")
parser.add_argument('--' + g_pkt_timeout_ms_key, default = g_def_pkt_timeout_ms, type = float,
        help = "packet receive timeout, in ms. default as {}".format(g_def_pkt_timeout_ms))
parser.add_argument('--' + g_dg_timeout_ms_key, default = g_def_dg_timeout_ms, type = float,
        help = "data group (15 packets) receive timeout, in ms. default as {}".format(g_def_dg_timeout_ms))
parser.add_argument('--' + g_max_ts_key, default = g_def_max_ts, type = int,
                help = "the max timestamp value. valid value is considered between [0, max_ts_key]."
                       "deault as {}".format(g_def_max_ts))
parser.add_argument('--' + g_expect_start_ts_key, default = g_def_expect_start_ts, type = int,
        help = "expected start ts. if not assigned, use the ts in the 1st sniffed pkt.")
parser.add_argument('--' + g_flush_cnt_key, default = g_def_flush_cnt, type = int,
        help = "assign an int number. output file is flushed every that number of dgs are processed."
               "increase this number may decrease process time but require more memory."
               " default as {}".format(g_def_flush_cnt))
parser.add_argument('--' + g_dup_pkt_rec_file_opt_key, default = g_def_dup_pkt_rec_file_name,
        help = "file to record duplicate pkt info. default as {}".format(g_def_dup_pkt_rec_file_name))
parser.add_argument('--' + g_discarded_pkt_rec_file_opt_key, default = g_def_discarded_pkt_rec_file_name,
        help = "file to record discared pkt(rb-full) info. default as {}".format(g_def_discarded_pkt_rec_file_name))
parser.add_argument('--' + g_expand_output_log_dgs_key, dest = g_expand_output_log_dgs_key, action = 'store_true',
        help = "expand lost dgs or not. if not expand, output is as 's~e lost' in one line;"
               " otherwise, each lost dg in one line")
parser.add_argument('--version', action = "version", version = "%(prog)s" + " " + g_version)

cmd_args = vars(parser.parse_args())
g_pacp_file_name = cmd_args[g_pacp_file_opt_key]
g_output_file_name = cmd_args[g_output_file_opt_key]
g_pkt_info_file_name = cmd_args[g_pkt_info_file_opt_key]

g_pkt_timeout_ms = cmd_args[g_pkt_timeout_ms_key]
g_dg_timeout_ms = cmd_args[g_dg_timeout_ms_key]
g_pkt_timeout_delta = timedelta(0, 0, g_pkt_timeout_ms * 1000) 
g_dg_timeout_delta = timedelta(0, 0, g_dg_timeout_ms * 1000) 

g_max_ts = cmd_args[g_max_ts_key]
g_max_ts_digits = len(str(g_max_ts))

g_expect_start_ts = cmd_args[g_expect_start_ts_key]

g_flush_cnt = cmd_args[g_flush_cnt_key]

g_dup_pkt_rec_file_name = cmd_args[g_dup_pkt_rec_file_opt_key]
g_discarded_pkt_rec_file_name = cmd_args[g_discarded_pkt_rec_file_opt_key]

g_expand_ouput_lost_dgs = cmd_args[g_expand_output_log_dgs_key]


print('{} is: {}'.format(g_pacp_file_opt_key, g_pacp_file_name))
print('{} is: {}'.format(g_output_file_opt_key, g_output_file_name))
if g_pkt_info_file_name: print('{} is: {}'.format(g_pkt_info_file_opt_key , g_pkt_info_file_name))

g_pacp_display_filter='(ip.src == 24.26.7.51) && (udp) && (ip.len>=100)'

#data begins with "bcbc". e.g.
#bc bc e1 00
#[0] is start byte number, and [1] is byte count. "*2" is becaue pkt.data.data is a string...
g_pkt_ele_pos_dict = \
{
    'cmd' :               [2 * 2, 1 * 2],
    'line_id' :           [0,     2 * 2],
    'ts' :                [0,     4 * 2],
    'row_no' :            [0,     1 * 2],
    'pkt_cnt_per_line' :  [0,     1 * 2],
    'pkt_no' :            [0,     1 * 2],
    'eng_area_id' :       [0,     2 * 2],
    'payload_size' :      [0,     2 * 2],
}
#init pkt structure definition
_tmp_pos, _tmp_len = g_pkt_ele_pos_dict['cmd'][0], g_pkt_ele_pos_dict['cmd'][1] 
for k in g_pkt_ele_pos_dict.keys():
    if 'cmd' != k:
        g_pkt_ele_pos_dict[k][0] = _tmp_pos + _tmp_len
        _tmp_pos, _tmp_len = g_pkt_ele_pos_dict[k][0], g_pkt_ele_pos_dict[k][1]

print(g_pkt_ele_pos_dict)
print("")

g_cmd_bytes_str = "e1"
def get_a_pkt(cap): 
    pkt = {'ret' : False}
    while True:
        try:
            udp_pkt = cap.next()
            #ds = str(udp_pkt.data.data)
            ds = udp_pkt.udp.payload.replace(":", "")
            if(ds[g_pkt_ele_pos_dict['cmd'][0] :  g_pkt_ele_pos_dict['cmd'][0] + g_pkt_ele_pos_dict['cmd'][1]] 
                         == g_cmd_bytes_str):
                pkt['ret'] = True
                pkt['sniff_time'] = udp_pkt.sniff_time
                pkt['number'] = udp_pkt.number
                pkt['info'] = dict()
                for k in g_pkt_ele_pos_dict.keys():
                    pkt['info'][k] \
                        = eval("0x" + ds[g_pkt_ele_pos_dict[k][0] : g_pkt_ele_pos_dict[k][0] + g_pkt_ele_pos_dict[k][1]]) 
                return pkt 
        except StopIteration:
            break;
    return pkt

g_statistics_dict = \
{
    'total_pkt(no-dup)' : 0,
    'dup_pkt' : 0,
    'discarded_pkt(rb-full)' : 0,
    'total_dg' : 0,
    '\tgood_dg' : 0,
    '\tbad_dg' : 0,
    '\t\tincomplete_dg' : 0,
    '\t\ttimeout_dg' : 0,
    '\t\tlost_dg' : 0,
}
g_except_pkt_number_dict = \
{
    'dup_pkt' : \
            {'fn' : g_dup_pkt_rec_file_name, 'header' : "|No.|ts|pkt_no|sniff_time|", 'data' : []},
    'discarded_pkt(rb-full)' :\
            {'fn' : g_discarded_pkt_rec_file_name, 'header' : "|No.|ts|pkt_no|sniff_time|", 'data' : []}
}

def count_a_new_dg(pkt_info):
    """
    status: 
        incomp: incomplete
        lost: lost
        good: completed
        timeout: timeout
    """
    data_group = dict()
    data_group['number'] = pkt_info['number']
    data_group['ts'] = pkt_info['info']['ts']
    data_group['pkt_cnt_per_line'] = pkt_info['info']['pkt_cnt_per_line']
    data_group['pkt_no'] = [pkt_info['info']['pkt_no']]
    data_group['min_sniff_time'] = pkt_info['sniff_time']
    data_group['max_sniff_time'] = pkt_info['sniff_time']
    data_group['status'] = 'incomp'
    return data_group

def count_and_output_dg(rl, d_g, rec_file):
    if 'lost' == d_g['status']:
        s, e = d_g['ts'], d_g['pkt_no']
        cnt = count_round_number(s, e, rl['capacity'])
        g_statistics_dict['\t\tlost_dg'] += cnt
        g_statistics_dict['\tbad_dg'] += cnt
        g_statistics_dict['total_dg'] += cnt
        if g_expand_ouput_lost_dgs:
            for i in range(cnt):
                print("{}\t".format(d_g['number']), file = rec_file, end = "")
                print("{:0{}}\t".format(s, g_max_ts_digits), file = rec_file, end = "")
                print(('\t' * 10) + d_g['status'], file = rec_file)
                s = (s + 1) % rl['capacity']
        else:
            print("{}\t".format(d_g['number']), file = rec_file, end = "")
            if s == e:
                print("{:0{}}\t".format(s, g_max_ts_digits), file = rec_file, end = "")
                print(('\t' * 10) + d_g['status'], file = rec_file)
            else:
                print("{:0{}}~{:0{}}\t".format(s, g_max_ts_digits, e, g_max_ts_digits), file = rec_file, end = "")
                print(('\t' * 9) + d_g['status'] + '(' + str(cnt) + ')', file = rec_file)
        return

    g_statistics_dict['total_dg'] += 1
    print("{}\t".format(d_g['number']), file = rec_file, end = "")
    print("{:0{}}\t".format(d_g['ts'], g_max_ts_digits), file = rec_file, end = "")

    min_dt_s = d_g['min_sniff_time'].strftime("%Y%m%d-%H:%M:%S.%f")
    max_dt_s = d_g['max_sniff_time'].strftime("%Y%m%d-%H:%M:%S.%f")
    t_delta = d_g['max_sniff_time'] - d_g['min_sniff_time']
    print(min_dt_s + "\t" + max_dt_s + "\t", file = rec_file, end = "")
    t_delta_us = t_delta.seconds * 1000000 + t_delta.microseconds
    print(str(t_delta_us) + "\t\t", file = rec_file, end = "")
    print(d_g['status'] + '\t', file = rec_file, end = "")
    if 'good' == d_g['status']:
        g_statistics_dict['\tgood_dg'] += 1
        g_statistics_dict['total_pkt(no-dup)'] += d_g['pkt_cnt_per_line']
    else:
        if 'timeout' == d_g['status']:
            g_statistics_dict['\t\ttimeout_dg'] += 1
        else: #imcomplete
            g_statistics_dict['\t\tincomplete_dg'] += 1
        g_statistics_dict['\tbad_dg'] += 1
        g_statistics_dict['total_pkt(no-dup)'] += len(d_g['pkt_no'])
        print('-'.join(map(str, d_g['pkt_no'])) + "\t", file = rec_file, end = "")

    print("", file = rec_file)

def count_and_output_lost_dgs(rl, s, e, rec_file, e_inc = False):
    """
    for 'lost' dg, 'ts' indicates start ts, 'pkt_no' indicates end (inclusive) ts.
    """
    dg = dict()
    dg['number'] = -1
    dg['ts'] = s
    dg['pkt_no'] = e if e_inc else ((e + rl['capacity'] - 1) % rl['capacity'])
    dg['status'] = 'lost'
    count_and_output_dg(rl, dg, rec_file)

def refresh_dgs_part(rl, till_node, rec_file):
    if till_node == None: return

    s_node, e_node = rl['head'], till_node
    before_extra = after_extra = False
    if not in_round_range(rl['ctrl_blk']['expect_min_ts'], s_node['idx'], e_node['idx'], rl['capacity'], True, True):
        n_h_dist = count_round_number(rl['ctrl_blk']['expect_min_ts'], rl['head']['idx'], rl['capacity'], False)
        t_n_dist = count_round_number(rl['tail']['idx'], rl['ctrl_blk']['expect_min_ts'], rl['capacity'], False)
        if n_h_dist < t_n_dist: before_extra = True
        else: after_extra = True

    dg = dict()
    dg['ts'] = 0
    dg['status'] = 'lost'
    s_ts, e_ts = s_node['idx'], e_node['idx']
    if before_extra: count_and_output_lost_dgs(rl, rl['ctrl_blk']['expect_min_ts'], s_ts, rec_file)

    #output s_node to e_node, inclusive.
    finished = False
    while not finished:
        idx = s_node['idx']
        count_and_output_dg(rl, s_node['data'], rec_file)
        if not(s_node is e_node):
            inc_idx_by_1 = (idx + 1) % rl['capacity']
            if inc_idx_by_1 != s_node['next']['idx']:
                count_and_output_lost_dgs(rl, inc_idx_by_1, s_node['next']['idx'], rec_file)
        else:
            finished = True
        tmp = s_node
        s_node = s_node['next']
        del_node_from_ring_link(rl, tmp)

    
    if after_extra: count_and_output_lost_dgs(rl, e_ts, rl['ctrl_blk']['expect_min_ts'], rec_file)

    rl['ctrl_blk']['expect_min_ts'] = (e_ts + 1) % rl['capacity']

    if ring_link_is_empty(rl): rl['ctrl_blk']['min_t_node'] = None
    else:
        min_t_n = rl['head']
        curr_n = rl['head']['next']
        while not(curr_n is rl['head']):
            if curr_n['data']['min_sniff_time'] < min_t_n['data']['min_sniff_time']: min_t_n = curr_n
            curr_n = curr_n['next']
        rl['ctrl_blk']['min_t_node'] = min_t_n

####################################################################################################

try:
    g_data_group_file = open(g_output_file_name, "w")
    print("No.\t时间戳\t最小时间\t\t\t最大时间\t\t\t时间差(us)\t是否完整\t包序号", file = g_data_group_file)
except IOError:
    print("Open output file " + g_output_file_name + " error.")
    sys.exit(-1)

if g_pkt_info_file_name != "":
    try:
        g_pkt_info_file = open(g_pkt_info_file_name, "w")
        print("No.|sniff_time|", file = g_pkt_info_file, end = "")
        for k in g_pkt_ele_pos_dict.keys(): print(k + "|", file = g_pkt_info_file, end = "")
        print("", file = g_pkt_info_file)
    except IOError:
        print("Open pkt_info file " + g_pkt_info_file_name + " error.")
        sys.exit(-2)

g_captured_pkts = pyshark.FileCapture(g_pacp_file_name, display_filter=g_pacp_display_filter, keep_packets = False)


g_start_dt = datetime.datetime.now()
print(g_start_dt.strftime("%Y%m%d-%H:%M:%S.%f") + " start process")
print("\nprocessing...\n")

g_dg_ring_link = init_ring_link(g_max_ts + 1)
g_dg_ring_link['ctrl_blk'] = dict()
g_dg_ring_link['ctrl_blk']['min_t_node'] = None
#g_dg_ring_link['ctrl_blk']['expect_min_ts'] = g_expect_start_ts

g_cnt_idx = 0
g_is_first_pkt = True
while True:
    ret = get_a_pkt(g_captured_pkts)
    if not(ret['ret']):
        print("\nNo more pkts.\n")
        break

    if g_pkt_info_file_name != "":
        print(ret['number'] + "|", file = g_pkt_info_file, end = "")
        print(ret['sniff_time'].strftime("%H:%M:%S.%f") + "|", file = g_pkt_info_file, end = "")
        for k in ret['info'].keys():
            print(str(ret['info'][k]) + "|", file = g_pkt_info_file, end = "")
        print("", file = g_pkt_info_file)

    ts = ret['info']['ts']
    if g_is_first_pkt:
        g_dg_ring_link['ctrl_blk']['expect_min_ts'] = ts if g_expect_start_ts < 0 else g_expect_start_ts
        g_is_first_pkt = False

    sniff_t = ret['sniff_time']
    sniff_t_str = sniff_t.strftime("%Y%m%d-%H:%M:%S.%f")
    curr_node = None
    if ts not in g_dg_ring_link['indices'].keys():
        new_dg = count_a_new_dg(ret)
        curr_node = get_a_new_ring_link_node(ts)
        curr_node['data'] = new_dg
        ins_ret = insert_node_into_ring_link(g_dg_ring_link, curr_node)
        if ins_ret != 'normal':
            g_statistics_dict['discarded_pkt(rb-full)'] += 1
            g_except_pkt_number_dict['discarded_pkt(rb-full)']['data'].append(dict({'number': ret['number'], 'ts': ts, 
                'pkt_no': ret['info']['pkt_no'], 'sniff_time': sniff_t_str}))
            print("No. {}: discared due to ring link full: ts-{}, pkt_no-{}, time-{}".format(ret['number'], 
                ts, ret['info']['pkt_no'], sniff_t_str))
            #continue
        else:
            if g_dg_ring_link['ctrl_blk']['min_t_node'] == None:
                g_dg_ring_link['ctrl_blk']['min_t_node'] = curr_node
    else:
        curr_node = g_dg_ring_link['indices'][ts]
        pkt_t_delta = sniff_t - curr_node['data']['min_sniff_time']
        if pkt_t_delta <= g_pkt_timeout_delta:
            if ret['info']['pkt_no'] in curr_node['data']['pkt_no']: 
                g_statistics_dict['dup_pkt'] += 1
                g_except_pkt_number_dict['dup_pkt']['data'].append(dict({'number': ret['number'], 'ts': ts, 
                    'pkt_no': ret['info']['pkt_no'], 'sniff_time': sniff_t_str}))
                print("No. {}: duplicate pkt_no {} in ts-{}, time-{}".format(ret['number'],
                                ret['info']['pkt_no'], ts, sniff_t_str))
                #continue
            else:
                curr_node['data']['pkt_no'].append(ret['info']['pkt_no'])
                #this < branch should not be entered because we assume sniff time is in ascendant order
                #if(sniff_t < curr_node['data']['min_sniff_time']):
                #    curr_node['data']['min_sniff_time'] = sniff_t
                if(sniff_t > curr_node['data']['max_sniff_time']):
                    curr_node['data']['max_sniff_time'] = sniff_t
                if(len(curr_node['data']['pkt_no']) >= curr_node['data']['pkt_cnt_per_line']):
                    #a good data group
                    curr_node['data']['status'] = 'good'
        else:
            curr_node['data']['status'] = 'timeout'
            refresh_dgs_part(g_dg_ring_link, curr_node, g_data_group_file)
            new_dg = count_a_new_dg(ret)
            curr_node = get_a_new_ring_link(ts)
            curr_node['data'] = new_dg
            insert_node_into_ring_link(g_dg_ring_link, curr_node)

    min_t_n = g_dg_ring_link['ctrl_blk']['min_t_node']
    dg_t_delta = sniff_t - min_t_n['data']['min_sniff_time']
    if dg_t_delta >= g_dg_timeout_delta:
        e_n = min_t_n['next']
        while not(e_n is g_dg_ring_link['head']) \
            and (sniff_t - e_n['data']['min_sniff_time'] >= g_dg_timeout_delta):
            e_n = e_n['next']
        if e_n is g_dg_ring_link['head']: e_n = e_n['prev']
        refresh_dgs_part(g_dg_ring_link, e_n, g_data_group_file)
        
    g_cnt_idx += 1
    if g_cnt_idx >= g_flush_cnt:
        g_data_group_file.flush()
        if g_pkt_info_file_name != "":
            g_pkt_info_file.flush()
        g_cnt_idx = 0

#if there are remaining pkts, they are all bad.
refresh_dgs_part(g_dg_ring_link, g_dg_ring_link['tail'], g_data_group_file)

print("", file = g_data_group_file)
for k, v in g_statistics_dict.items(): 
    print(k + ": " + str(v))
    print(k + ": " + str(v), file = g_data_group_file)
bad_dg_ratio = 0 if 0 == g_statistics_dict['total_dg'] \
                else g_statistics_dict['\tbad_dg']/float(g_statistics_dict['total_dg'])
bg_dg_r_s = "bad data group ration: {:.2%}".format(bad_dg_ratio)
print("\n" + bg_dg_r_s , file = g_data_group_file)
print("\n" + bg_dg_r_s)

g_end_dt = datetime.datetime.now()
print(g_end_dt.strftime("\n%Y%m%d-%H:%M:%S.%f") + " end process.")
g_used_time_dura = g_end_dt - g_start_dt
time_elapsed_str = "time elapsed: {} days, {} seconds, {} us".format(g_used_time_dura.days, g_used_time_dura.seconds,  g_used_time_dura.microseconds)
print("\n" + time_elapsed_str, file = g_data_group_file)
print("\n" + time_elapsed_str)

g_data_group_file.close()
if g_pkt_info_file_name != "":
    g_pkt_info_file.close()

for k,v in g_except_pkt_number_dict.items(): 
    if len(v['data']) > 0:
        fn = open(v['fn'], "w")
        if fn:
            print(v['header'], file = fn)
            for i in range(len(v['data'])): 
                print("|", end = "", file = fn)
                for kk, vv in v['data'][i].items():
                    print(vv, end = "", file = fn)
                    print("|", end = "", file = fn)
                print("", file = fn)
            fn.close()

print("\nFinished. Please check the result file: " + g_output_file_name)
