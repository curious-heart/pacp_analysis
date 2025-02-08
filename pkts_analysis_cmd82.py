import pyshark
import datetime
from datetime import timedelta
import sys
import os
import argparse
from ring_link.ring_link import *

g_version = '1.00.00'
g_app_name = os.path.basename(__file__).split('.')[0]

"""
assumption: sniff time is in ascendant order.
"""

g_pacp_file_opt_key = 'pacp_file'

g_output_file_opt_key = 'output_file'
g_def_output_file_name = "data_statistics.txt" 

g_expect_start_ts_key = 'start_ts'
g_def_expect_start_ts = -1
g_start_ts_find_time_int_key = 'start_ts_find_time_int'
g_def_start_ts_find_time_int = 10 #sec
g_start_ts_find_ts_int_key = 'start_ts_find_ts_int'
g_def_start_ts_find_ts_int = 10 # #
g_start_ts_find_ts_count_key = 'start_ts_find_ts_count'
g_def_start_ts_find_ts_count = 10 # #
g_ts_overload_period_key = 'ts_overload_p_s'
g_def_ts_overload_period_s = -1
g_discarded_pkt_rec_file_opt_key = 'discarded_pkt_file'
g_def_discarded_pkt_rec_file_name = "discarded_pkts.txt"
g_max_ts_key = 'max_ts_key'
g_def_max_ts = 65535

g_dup_pkt_rec_file_opt_key = 'dup_pkt_file'
g_def_dup_pkt_rec_file_name = "duplicate_pkts.txt"

g_expand_output_log_dgs_key = 'expand_lost_pkts'
g_min_valid_pkt_len_key = 'min_valid_pkt_len'
g_def_min_valid_pkt_len = 100

parser = argparse.ArgumentParser(prog = g_app_name)
parser.add_argument(g_pacp_file_opt_key, default = "", help = "pacp file name")
parser.add_argument('-o', '--' + g_output_file_opt_key, default = g_def_output_file_name, 
        help = "output file name. default as {}".format(g_def_output_file_name))
parser.add_argument('--' + g_expect_start_ts_key, default = g_def_expect_start_ts, type = int,
        help = "expected start ts. if not assigned, use the the 'round-minimum' ts before the 1st sniffed pkt.")
parser.add_argument('--' + g_start_ts_find_time_int_key, default = g_def_start_ts_find_time_int, type = float,
        help = "time interval in seconds. used to find the the 'round-minimum' ts before the 1st sniffed pkt."
               "only valid if --{} is not assigned.".format(g_expect_start_ts_key))
parser.add_argument('--' + g_start_ts_find_ts_int_key, default = g_def_start_ts_find_ts_int, type = int,
        help = "timestamp interval. used to find the the 'round-minimum' ts before the 1st sniffed pkt."
               "only valid if --{} is not assigned.".format(g_expect_start_ts_key))
parser.add_argument('--' + g_start_ts_find_ts_count_key, default = g_def_start_ts_find_ts_count, type = int,
        help = "timestamp count. used to find the the 'round-minimum' ts before the 1st sniffed pkt."
               "only valid if --{} is not assigned.".format(g_expect_start_ts_key))
parser.add_argument('--' + g_ts_overload_period_key, default = g_def_ts_overload_period_s, type = float,
        help = "a time duration in seconds, in which we think all timestamp are not overload.")
parser.add_argument('--' + g_discarded_pkt_rec_file_opt_key, default = g_def_discarded_pkt_rec_file_name,
        help = "file to record discared pkt(rb-full) info. default as {}".format(g_def_discarded_pkt_rec_file_name))
parser.add_argument('--' + g_max_ts_key, default = g_def_max_ts, type = int,
                help = "the max timestamp value. valid value is considered between [0, max_ts_key]."
                       "deault as {}".format(g_def_max_ts))
parser.add_argument('--version', action = "version", version = "%(prog)s" + " " + g_version)

parser.add_argument('--' + g_dup_pkt_rec_file_opt_key, default = g_def_dup_pkt_rec_file_name,
        help = "file to record duplicate pkt info. default as {}".format(g_def_dup_pkt_rec_file_name))
parser.add_argument('--' + g_min_valid_pkt_len_key, default = g_def_min_valid_pkt_len, type = int,
        help = "the mininum len of packet that are taken as valid."
                "used as pcap filter. default as {}.".format(g_def_min_valid_pkt_len))
parser.add_argument('--' + g_expand_output_log_dgs_key, dest = g_expand_output_log_dgs_key, action = 'store_true',
        help = "expand lost dgs or not. if not expand, output is as 's~e lost' in one line;"
               " otherwise, each lost dg in one line")

cmd_args = vars(parser.parse_args())
g_pacp_file_name = cmd_args[g_pacp_file_opt_key]
g_output_file_name = cmd_args[g_output_file_opt_key]
g_expect_start_ts = cmd_args[g_expect_start_ts_key]
g_start_ts_find_time_int = cmd_args[g_start_ts_find_time_int_key]
g_start_ts_find_time_int_delta = timedelta(0, 0, g_start_ts_find_time_int * 1000) \
                                    if g_start_ts_find_time_int > 0 else timedelta(0, 0, 0)
g_start_ts_find_ts_int = cmd_args[g_start_ts_find_ts_int_key]
g_start_ts_find_ts_count = cmd_args[g_start_ts_find_ts_count_key]
g_ts_overload_period = cmd_args[g_ts_overload_period_key]
g_ts_overload_period_delta = timedelta(0, 0, g_ts_overload_period * 1000) \
                                    if g_ts_overload_period > 0 else timedelta(0, 0, 0)
g_discarded_pkt_rec_file_name = cmd_args[g_discarded_pkt_rec_file_opt_key]
g_max_ts = cmd_args[g_max_ts_key]
g_max_ts_digits = len(str(g_max_ts))

g_dup_pkt_rec_file_name = cmd_args[g_dup_pkt_rec_file_opt_key]
g_expand_ouput_lost_pkts = cmd_args[g_expand_output_log_dgs_key]
g_min_valid_pkt_len = cmd_args[g_min_valid_pkt_len_key]

print('{} is: {}'.format(g_pacp_file_opt_key, g_pacp_file_name))
print('{} is: {}'.format(g_output_file_opt_key, g_output_file_name))
print('{} is: {}'.format(g_discarded_pkt_rec_file_opt_key, g_discarded_pkt_rec_file_name))

#data begins with "bcbc". e.g.
#bc bc e1 00
g_payload_ending_bytes_num = 6 #data ends with 4 bytes crc and "fcfc".
#[0] is start byte number, and [1] is byte count. "*2" is becaue pkt.data.data is a string...
g_pkt_ele_pos_dict = \
{
    'cmd' :               [2 * 2, 1 * 2],
    'op_code' :           [0,     1 * 2],
    'payload_size' :      [0,     2 * 2],
    'ts' :                [0,     4 * 2],
    'data_bytes' :        [0,     0],
}
#init pkt structure definition
_tmp_pos, _tmp_len = g_pkt_ele_pos_dict['cmd'][0], g_pkt_ele_pos_dict['cmd'][1] 
for k in g_pkt_ele_pos_dict.keys():
    if 'cmd' != k:
        g_pkt_ele_pos_dict[k][0] = _tmp_pos + _tmp_len
        _tmp_pos, _tmp_len = g_pkt_ele_pos_dict[k][0], g_pkt_ele_pos_dict[k][1]

print(g_pkt_ele_pos_dict)
print("")

g_cmd_bytes_str = "82"
def get_a_pkt(cap): 
    pkt = {'ret' : False}
    while True:
        try:
            udp_pkt = cap.next()
            #ds = str(udp_pkt.data.data)
            ds = udp_pkt.udp.payload.raw_value
            if(ds[g_pkt_ele_pos_dict['cmd'][0] :  g_pkt_ele_pos_dict['cmd'][0] + g_pkt_ele_pos_dict['cmd'][1]] 
                         == g_cmd_bytes_str):
                pkt['ret'] = True
                pkt['sniff_time'] = udp_pkt.sniff_time
                pkt['number'] = udp_pkt.number
                pkt['info'] = dict()
                for k in g_pkt_ele_pos_dict.keys():
                    if 'data_bytes' != k: 
                        pkt['info'][k] \
                        = eval("0x" + ds[g_pkt_ele_pos_dict[k][0] : g_pkt_ele_pos_dict[k][0] + g_pkt_ele_pos_dict[k][1]])
                    else: 
                        pkt['info'][k] = ds

                return pkt 
        except StopIteration:
            break;
    return pkt

g_statistics_dict = \
{
    'total_pkt' : 0,
    'dup_pkt' : 0,
    'discarded_pkt(wrong_len)' : 0,
    'lost_pkt' : 0
}
g_discarded_pkt_rec_dict = \
{
    'fn' : g_discarded_pkt_rec_file_name,
    'header' : "|No.|ts|pkt_no|sniff_time|",
    'pkts' : [] #every item is a dict: {'should_be_len': 0, 'len': 0, 'data': []}
}

def count_and_output_dg(rl, d_g, rec_file):
    if 'lost' == d_g['status']:
        s, e = d_g['ts'], d_g['pkt_no']
        cnt = count_round_number(s, e, rl['capacity'])
        if g_expand_ouput_lost_pkts:
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
        g_statistics_dict['total_pkt'] += d_g['pkt_cnt_per_line']
    else:
        g_statistics_dict['total_pkt'] += len(d_g['pkt_no'])
        print('-'.join(map(str, d_g['pkt_no'])) + "\t", file = rec_file, end = "")

    print("", file = rec_file)

def ts_is_valid(ts):
    return (0 <= ts) and (ts <= g_max_ts)

def get_a_new_cust_node(ts, tk):
    node = get_a_new_ring_link_node(ts)
    node['data'] = [] #every item is a dict returned by get_a_pkt
    node['first_sniff_time'] = tk

def set_start_ts():
    if (ts_is_valid(g_dg_ring_link['ctrl_blk']['start_ts']) or 
       (None == g_dg_ring_link['ctrl_blk']['first_pkt_node']) or
       (len(g_dg_ring_link['ctrl_blk']['first_pkt_node']['data']) <= 0)):
        return
    first_pkt_ts = g_dg_ring_link['ctrl_blk']['first_pkt_node']['idx']

    ts_int_f_pkt_ts = round_sub(first_pkt_ts, g_start_ts_find_ts_int) if g_start_ts_find_ts_int > 0 else first_pkt_ts
    while ((None == g_dg_ring_link['ctrl_blk']['indices'][ts_int_f_pkt_ts]) and (ts_int_f_pkt_ts != first_pkt_ts)):
        ts_int_f_pkt_ts = round_add(ts_int_f_pkt_ts, 1)
    ts_int_f_node = g_dg_ring_link['ctrl_blk']['indices'][ts_int_f_pkt_ts]

    time_int_f_node = g_dg_ring_link['ctrl_blk']['first_pkt_node']['prev']
    if g_start_ts_find_time_int > 0:
        while ((time_int_f_node != g_dg_ring_link['ctrl_blk']['first_pkt_node']) and 
            (abs(time_int_f_node['first_sniff_time'] - g_dg_ring_link['ctrl_blk']['first_pkt_node']['first_sniff_time'])
                    > g_start_ts_find_time_int_delta)):
            time_int_f_node = time_int_f_node['prev']
    time_int_f_pkt_ts = time_int_f_node['first_sniff_time']

    if count_round_number(ts_int_f_pkt_ts, first_pkt_ts) <= count_round_number(time_int_f_pkt_ts, first_pkt_ts):
        former_ptk_ts = ts_int_f_pkt_ts
        former_node = ts_int_f_node
    else:
        former_ptk_ts = time_int_f_pkt_ts
        former_node = time_int_f_node

    g_dg_ring_link['ctrl_blk']['start_ts'] = former_pkt_ts
    g_dg_ring_link['ctrl_blk']['start_ts_node'] = former_node

def hex_digit_char_OR(c1, c2, capital = False):
    """
    c1 and c2 should be hex digtit char, e.g., '0', '1', 'a', 'B'.
    return value v is char,  order(v) is c1 | c2. (c1 and c2 are first converted into digit and then OR)
    """
    letter_a = 'A' if capital else 'a'
    letter_f = 'F' if capital else 'A'

    d_c1 = ((order(c1) - order(letter_a) + 10) if (letter_a <= c1 and c1 <= letter_f) else (order(c1) - order('0')))
    d_c2 = ((order(c2) - order(letter_a) + 10) if (letter_a <= c2 and c2 <= letter_f) else (order(c2) - order('0')))
    ORed_d = d_c1 | d_c2

    if(10 <= ORed_d and ORed_d <= 15): v_ch = chr(ORed_d - 10 + ord(letter_a))
    else: v_ch = chr(ORed_d + ord('0'))
    return v_ch

_g_lost_pkt_ts_arr = []
def rec_pkt_data(ts, node, d_str, merged, rec_file):
    #print("首包编号\t时间戳\t包数量\t合并数据\t包编号列表", file = g_pkt_rec_file)
    if (None == node) or (len(node['data']) == 0): #lost
        if g_expand_ouput_lost_pkts:
            print("{:0{}}(lost)\t".format(ts, g_max_ts_digits), file = rec_file)
        else:
            _g_lost_pkt_ts_arr.append(ts)
        return
    if len(_g_lost_pkt_ts_arr) > 0:
        if(len(_g_lost_pkt_ts_arr) > 1):
            print("{:0{}} ~ {:0{}}(lost)\t".format(_g_lost_pkt_ts_arr[0], g_max_ts_digits, 
                                           _g_lost_pkt_ts_arr[-1],g_max_ts_digits), file = rec_file)
        else:
            print("{:0{}}(lost)\t".format(_g_lost_pkt_ts_arr[0], g_max_ts_digits), file = rec_file)
        _g_lost_pkt_ts_arr.clear()
    first_pkt_no = node['data'][0]['number']
    pkt_ts = ts
    pkt_cnt = len(node['data'])
    data_str = node['data'][0]['data_bytes'][0 : g_pkt_ele_pos_dict['data_bytes'][0]] + d_str
    pkt_no_list = tuple(node['data'][i]['number'] for i in range(pkt_cnt))

def refresh_stat():
    if not ts_is_valid(g_dg_ring_link['ctrl_blk']['start_ts']):
        set_start_ts()

    s_ts = g_dg_ring_link['ctrl_blk']['start_ts']
    if not ts_is_valid(s_ts):
        print("\n\nError: start ts {} is not invalid!!!\n\n".format(s_ts))
        return

    end_idx = round_sub(s_ts, 1)
    while (end_idx != s_ts) and (None == g_dg_ring_link['ctrl_blk']['indices'][end_idx]):
        end_idx = round_sub(end_idx, 1)

    dbyte_pos = g_pkt_ele_pos_dict['data_bytes'][0]
    idx = s_ts
    while True:
        merged_data = False
        curr_node = g_dg_ring_link['ctrl_blk']['indices'][idx]
        d_str = ""
        if (None == curr_node) or (len(curr_node['data']) == 0):
            g_statistics_dict['lost_pkt'] += 1
            g_statistics_dict['total_pkt'] += 1
        elif len(curr_node['data']) > 1: #dup pkts exists
            merged_data = True
            pkt_cnt = len(curr_node['data'])
            g_statistics_dict['total_pkt'] += pkt_cnt 
            g_statistics_dict['dup_pkt'] += pkt_cnt 
            pkt_len = curr_node['data'][0]['info']['payload_size']
            d_str = '0' * (pkt_len * 2)
            for p_idx in range(pkt_cnt):
                pkt = curr_node['data'][p_idx]
                if pkt['info']['payload_size'] != pkt_len:
                    g_statistics_dict['discarded_pkt(wrong_len)'] += 1
                    g_discarded_pkt_rec_dict['pkts'].append(dict('should_be_len' = pkt_len, 
                                                                 'len' = pkt['info']['payload_size'],
                                                                 'data' = pkt))
                else:
                    #now merge data
                    d_str = ''.join(hex_digit_char_OR(d_str[i], pkt['info']['data_btyes'][dbyte_pos][i])
                                        for i in range(pkt_len))
        else: #single pkt
            g_statistics_dict['total_pkt'] += 1
            d_str = pkt['info']['data_btyes'][dbyte_pos : dbyte_pos + pkt_len]

        rec_pkt_data(idx, curr_node, d_str, merged_data, g_pkt_rec_file)
        del_node_from_ring_link(g_dg_ring_link, curr_node)

        idx = round_add(idx, 1)
        if round_add(end_idx, 1) == idx:
            break
####################################################################################################

try:
    g_pkt_rec_file = open(g_output_file_name, "w")
    print("首包编号\t时间戳\t包数量\t合并数据\t包编号列表", file = g_pkt_rec_file)
except IOError:
    print("Open output file " + g_output_file_name + " error.")
    sys.exit(-1)

g_captured_pkts = pyshark.FileCapture(g_pacp_file_name, keep_packets = False)

g_start_dt = datetime.datetime.now()
print(g_start_dt.strftime("%Y%m%d-%H:%M:%S.%f") + " start process")
print("\nprocessing...\n")

g_dg_ring_link = init_ring_link(g_max_ts + 1)
g_dg_ring_link['ctrl_blk'] = dict(
        'start_ts' = g_expect_start_ts, 
        'start_ts_node' = None,
        'first_pkt_time' = 0,
        'first_pkt_node' = None,
        )

g_is_first_pkt = True
while True:
    ret = get_a_pkt(g_captured_pkts)
    if not(ret['ret']):
        print("\nNo more pkts.\n")
        break

    sniff_t = ret['sniff_time']
    sniff_t_str = sniff_t.strftime("%Y%m%d-%H:%M:%S.%f")
    ts = ret['info']['ts']
    if g_is_first_pkt:
        g_dg_ring_link['ctrl_blk']['first_pkt_time'] = sniff_t
        g_dg_ring_link['ctrl_blk']['first_pkt_node'] = node
        g_is_first_pkt = False

    if ts not in g_dg_ring_link['indices'].keys():
        node = get_a_new_cust_node(ts, sniff_t)
    else:
        node = g_dg_ring_link['indices'][ts]
    if (g_ts_overload_period > 0) and (sniff_t - node['first_sniff_time'] > g_ts_overload_period_delta):
        #should check ts overload
        refresh_stat()
    else:
        node['data'].append(ret)

refresh_stat()

print("", file = g_pkt_rec_file)
for k, v in g_statistics_dict.items(): 
    print(k + ": " + str(v))
    print(k + ": " + str(v), file = g_pkt_rec_file)

g_end_dt = datetime.datetime.now()
print(g_end_dt.strftime("\n%Y%m%d-%H:%M:%S.%f") + " end process.")
g_used_time_dura = g_end_dt - g_start_dt
time_elapsed_str = "time elapsed: {} days, {} seconds, {} us".format(g_used_time_dura.days, g_used_time_dura.seconds,  g_used_time_dura.microseconds)
print("\n" + time_elapsed_str, file = g_pkt_rec_file)
print("\n" + time_elapsed_str)
print("\n\n(" + g_app_name + " " + g_version + ")", file = g_pkt_rec_file)
print("\n\n(" + g_app_name + " " + g_version + ")")

g_pkt_rec_file.close()

print("\nFinished. Please check the result file: " + g_output_file_name)
