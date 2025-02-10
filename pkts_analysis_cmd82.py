import pyshark
import datetime
from datetime import timedelta
import sys
import os
import argparse
from ring_link.ring_link import *

g_version = '1.01.00'
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
g_ts_overload_period_key = 'ts_overload_p_s'
g_def_ts_overload_period_s = -1
g_discarded_pkt_rec_file_opt_key = 'discarded_pkt_file'
g_def_discarded_pkt_rec_file_name = "discarded_pkts.txt"
g_max_ts_key = 'max_ts_key'
g_def_max_ts = 65535

g_dup_pkt_rec_file_opt_key = 'dup_pkt_file'
g_def_dup_pkt_rec_file_name = "duplicate_pkts.txt"

g_min_valid_pkt_len_key = 'min_valid_pkt_len'
g_def_min_valid_pkt_len = 58

g_expand_output_log_dgs_key = 'expand_lost_pkts'

g_display_from_1st_pkt_key = "display_from_1st_pkt"

g_flush_cnt_key = 'flush_cnt'
g_def_flush_cnt = 100 * 15

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
parser.add_argument('--' + g_ts_overload_period_key, default = g_def_ts_overload_period_s, type = float,
        help = "a time duration in seconds, in which we think all timestamp are not overload. "
           "if it is less than 0, all ts are taken as not overload. default as {}.".format(g_def_ts_overload_period_s))
parser.add_argument('--' + g_discarded_pkt_rec_file_opt_key, default = g_def_discarded_pkt_rec_file_name,
        help = "file to record discared pkt(wrong len) info. default as {}".format(g_def_discarded_pkt_rec_file_name))
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
parser.add_argument('--' + g_display_from_1st_pkt_key, dest = g_display_from_1st_pkt_key, action = 'store_true',
        help = "display result keys from the 1st pkt in pcapng file. by default, display from the pkt with start ts.")

parser.add_argument('--' + g_flush_cnt_key, default = g_def_flush_cnt, type = int,
        help = "assign an int number. output file is flushed every that number of dgs are processed."
               "increase this number may decrease process time but require more memory."
               " default as {}".format(g_def_flush_cnt))

cmd_args = vars(parser.parse_args())
g_pacp_file_name = cmd_args[g_pacp_file_opt_key]
g_output_file_name = cmd_args[g_output_file_opt_key]
g_expect_start_ts = cmd_args[g_expect_start_ts_key]
g_start_ts_find_time_int = cmd_args[g_start_ts_find_time_int_key]
g_start_ts_find_time_int_delta = timedelta(0, 0, g_start_ts_find_time_int * 1000) \
                                    if g_start_ts_find_time_int > 0 else timedelta(0, 0, 0)
g_start_ts_find_ts_int = cmd_args[g_start_ts_find_ts_int_key]
g_ts_overload_period = cmd_args[g_ts_overload_period_key]
g_ts_overload_period_delta = timedelta(0, 0, g_ts_overload_period * 1000) \
                                    if g_ts_overload_period > 0 else timedelta(0, 0, 0)
g_discarded_pkt_rec_file_name = cmd_args[g_discarded_pkt_rec_file_opt_key]
g_max_ts = cmd_args[g_max_ts_key]
g_max_ts_digits = len(str(g_max_ts))

g_dup_pkt_rec_file_name = cmd_args[g_dup_pkt_rec_file_opt_key]
g_min_valid_pkt_len = cmd_args[g_min_valid_pkt_len_key]

g_expand_ouput_lost_pkts = cmd_args[g_expand_output_log_dgs_key]
g_display_from_1st_pkt = cmd_args[g_display_from_1st_pkt_key]

g_flush_cnt = cmd_args[g_flush_cnt_key]

def print_time_point(tp, prompt = "", end_str = "", endl = "\n", tgt = [sys.stdout]):
    o_str = "{}{}{}".format(prompt, tp.strftime("%Y%m%d-%H:%M:%S.%f"), end_str)
    for o_f in tgt:
        print(o_str, end = endl, file = o_f)

def print_time_dura(td, prompt = "", end_str = "", endl = "\n", tgt = [sys.stdout]):
    dura_str = "{}{} days, {} seconds, {} us{}".format(prompt, td.days, td.seconds, td.microseconds, end_str)
    for o_file in tgt:
        print(dura_str, end = endl, file = o_file)

def print_elapsed_time(s, e, prompt = "time elapsed: ", end_str = "", endl = "\n", tgt = [sys.stdout]):
    dura = e - s
    elapsed_str = "{}{} days, {} seconds, {} us{}".format(prompt, dura.days, dura.seconds, dura.microseconds, end_str)
    for o_file in tgt:
        print(elapsed_str, end = endl, file = o_file)

print('{} is: {}'.format(g_pacp_file_opt_key, g_pacp_file_name))
print('{} is: {}'.format(g_output_file_opt_key, g_output_file_name))
print('{} is: {}'.format(g_discarded_pkt_rec_file_opt_key, g_discarded_pkt_rec_file_name))

#g_pacp_display_filter='(ip.src == 24.26.7.51) && (udp) && (ip.len>={})'.format(g_min_valid_pkt_len)
g_pacp_display_filter='(udp) && (ip.len>={})'.format(g_min_valid_pkt_len)

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

g_start_dt = datetime.datetime.now()
print_time_point(g_start_dt, "",  " start process")
print("\nprocessing...\n")

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
    'header' : "|No.|ts|sniff_time|len|should_be_len|data|",
    'pkts' : [] #every item is a dict: {'should_be_len': 0, 'data': []}
}

def ts_is_valid(ts):
    return (0 <= ts) and (ts <= g_dg_ring_link['capacity'] - 1)

def get_a_new_cust_node(ts, tk):
    node = get_a_new_ring_link_node(ts)
    node['data'] = [] #every item is a dict returned by get_a_pkt
    node['first_sniff_time'] = tk
    return node

def set_start_ts():
    if (ts_is_valid(g_dg_ring_link['ctrl_blk']['start_ts']) or 
       (None == g_dg_ring_link['ctrl_blk']['first_pkt_node']) or
       (len(g_dg_ring_link['ctrl_blk']['first_pkt_node']['data']) <= 0)):
        return
    first_pkt_ts = g_dg_ring_link['ctrl_blk']['first_pkt_node']['idx']

    print("")
    print("first_pkt_ts is {}".format(first_pkt_ts))

    ts_int_f_pkt_ts = round_sub(first_pkt_ts, g_start_ts_find_ts_int) if g_start_ts_find_ts_int > 0 else first_pkt_ts
    while ((not (ts_int_f_pkt_ts in g_dg_ring_link['indices'].keys())) and (ts_int_f_pkt_ts != first_pkt_ts)):
        ts_int_f_pkt_ts = round_add(ts_int_f_pkt_ts, 1)
    ts_int_f_node = g_dg_ring_link['indices'][ts_int_f_pkt_ts]
    print("ts_int_f_pkt_ts is {}".format(ts_int_f_pkt_ts))

    time_int_f_node = g_dg_ring_link['ctrl_blk']['first_pkt_node']['prev']
    if g_start_ts_find_time_int > 0:
        while ((time_int_f_node != g_dg_ring_link['ctrl_blk']['first_pkt_node']) and 
            (abs(time_int_f_node['first_sniff_time'] - g_dg_ring_link['ctrl_blk']['first_pkt_node']['first_sniff_time'])
                    > g_start_ts_find_time_int_delta)):
            time_int_f_node = time_int_f_node['prev']
    time_int_f_pkt_ts = time_int_f_node['idx']
    print("time_int_f_pkt_ts is {}".format(time_int_f_pkt_ts))

    if count_round_number(ts_int_f_pkt_ts, first_pkt_ts) >= count_round_number(time_int_f_pkt_ts, first_pkt_ts):
        former_pkt_ts = ts_int_f_pkt_ts
        former_node = ts_int_f_node
    else:
        former_pkt_ts = time_int_f_pkt_ts
        former_node = time_int_f_node

    g_dg_ring_link['ctrl_blk']['start_ts'] = former_pkt_ts
    g_dg_ring_link['ctrl_blk']['start_ts_node'] = former_node


def hex_digit_char_OR(c1, c2, capital = False):
    """
    c1 and c2 should be hex digtit char, e.g., '0', '1', 'a', 'B'.
    return value v is char,  ord(v) is c1 | c2. (c1 and c2 are first converted into digit and then OR)
    """
    letter_a = 'A' if capital else 'a'
    letter_f = 'F' if capital else 'A'

    d_c1 = ((ord(c1) - ord(letter_a) + 10) if (letter_a <= c1 and c1 <= letter_f) else (ord(c1) - ord('0')))
    d_c2 = ((ord(c2) - ord(letter_a) + 10) if (letter_a <= c2 and c2 <= letter_f) else (ord(c2) - ord('0')))
    ORed_d = d_c1 | d_c2

    if(10 <= ORed_d and ORed_d <= 15): v_ch = chr(ORed_d - 10 + ord(letter_a))
    else: v_ch = chr(ORed_d + ord('0'))
    return v_ch

def sep_hex_str(s_str, sep):
    """
    used for the following case:
        input s_str = '0123', sep = ','
        return '01,23'
    """
    s_len = len(s_str)
    byte_list = [s_str[idx*2 : (idx*2)+2] for idx in range(int(s_len /2))]
    if len(byte_list) * 2 != s_len: byte_list.append(s_str[s_len - 1])
    return sep.join(byte_list)

_g_lost_pkt_ts_arr = []
_g_cnt_idx = 0
def rec_pkt_data(ts, node, invalid_pkt_cnt, d_str, rec_file):
    global _g_lost_pkt_ts_arr
    global _g_cnt_idx 
    #print("首包编号\t首包时间\t时间戳\t包数量\t有效包数量\t合并后数据\t包编号列表", file = g_pkt_rec_file)
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
    first_pkt_sniff_time_str = node['first_sniff_time'].strftime("%Y%m%d-%H:%M:%S.%f")
    pkt_ts = ts
    pkt_cnt = len(node['data'])
    valid_pkt_cnt = pkt_cnt - invalid_pkt_cnt
    data_str = node['data'][0]['info']['data_bytes'][0 : g_pkt_ele_pos_dict['data_bytes'][0]] + d_str
    sep_data_str = sep_hex_str(data_str, ' ')
    pkt_no_list = ','.join(node['data'][i]['number'] for i in range(pkt_cnt))

    print("{}\t{}\t{:0{}}\t{}\t{}\t{}\t{}"
        .format(first_pkt_no, first_pkt_sniff_time_str, pkt_ts, g_max_ts_digits, pkt_cnt, valid_pkt_cnt, 
                sep_data_str, pkt_no_list),
         file = rec_file)
    _g_cnt_idx += 1
    if _g_cnt_idx >= g_flush_cnt:
        rec_file.flush()
        _g_cnt_idx = 0

_g_refresh_stat_point = 0
def refresh_stat():
    global _g_refresh_stat_point
    refresh_point_dt = datetime.datetime.now()
    print_time_point(refresh_point_dt, "\trefresh point {}: ".format(_g_refresh_stat_point))
    print_elapsed_time(g_start_dt, refresh_point_dt, "\t\ttime elapsed: ")
    _g_refresh_stat_point += 1

    if g_dg_ring_link['cnt'] <= 0:
        print("\n\nNo valid pkt exist.!\n\n")
        g_dg_ring_link['ctrl_blk']['ts_in_capt_ord'].clear()
        return

    if not ts_is_valid(g_dg_ring_link['ctrl_blk']['start_ts']):
        set_start_ts()

    print("\nstart ts: {}\n".format(g_dg_ring_link['ctrl_blk']['start_ts']))

    s_ts = g_dg_ring_link['ctrl_blk']['start_ts']
    if not ts_is_valid(s_ts):
        print("\n\nError: start ts {} is not invalid!!!\n\n".format(s_ts))
        g_dg_ring_link['ctrl_blk']['ts_in_capt_ord'].clear()
        return

    start_idx = s_ts
    end_idx = round_sub(s_ts, 1)
    while (end_idx != s_ts) and (not(end_idx in g_dg_ring_link['indices'].keys())):
        end_idx = round_sub(end_idx, 1)

    if g_display_from_1st_pkt:
        capt_idx = 0
        display_curr_idx = g_dg_ring_link['ctrl_blk']['ts_in_capt_ord'][capt_idx]
        display_end_idx = round_sub(display_curr_idx, 1)
        idx_flag_marks = dict([(i, i) for i in range(g_dg_ring_link['capacity'])])
    else:
        display_curr_idx = start_idx
        display_end_idx = end_idx

    dbyte_pos = g_pkt_ele_pos_dict['data_bytes'][0] #not including ts
    while True:
        if not in_round_range(display_curr_idx, start_idx, end_idx, g_dg_ring_link['capacity'], True, True):
            display_curr_idx = round_add(display_curr_idx, 1)
            continue

        merged_data = False
        curr_node = g_dg_ring_link['indices'][display_curr_idx] if display_curr_idx in g_dg_ring_link['indices'].keys()\
                                                                else None
        d_str = ""
        invalid_pkt_cnt = 0
        discarded_pkts = dict([('should_be_len', 0), ('data', [])])
        if (None == curr_node) or (len(curr_node['data']) == 0):
            g_statistics_dict['lost_pkt'] += 1
            g_statistics_dict['total_pkt'] += 1
        else:
            pkt_len = curr_node['data'][0]['info']['payload_size'] * 2 - g_pkt_ele_pos_dict['ts'][1] #not including ts
            if len(curr_node['data']) > 1: #dup pkts exists
                merged_data = True
                pkt_cnt = len(curr_node['data'])
                g_statistics_dict['total_pkt'] += pkt_cnt 
                g_statistics_dict['dup_pkt'] += pkt_cnt 
                d_str = '0' * pkt_len
                for p_idx in range(pkt_cnt):
                    pkt = curr_node['data'][p_idx]
                    if pkt['info']['payload_size'] * 2 != (pkt_len + g_pkt_ele_pos_dict['ts'][1]):
                        g_statistics_dict['discarded_pkt(wrong_len)'] += 1
                        discarded_pkts['data'].append(pkt)
                        invalid_pkt_cnt += 1
                    else:
                        #now merge data
                        d_str = ''.join(hex_digit_char_OR(d_str[i], pkt['info']['data_bytes'][dbyte_pos + i])
                                            for i in range(pkt_len))
                if len(discarded_pkts['data']) > 0:
                    discarded_pkts['should_be_len'] = pkt_len
                    g_discarded_pkt_rec_dict['pkts'].append(discarded_pkts)
            else: #single pkt
                pkt = curr_node['data'][0]
                d_str = pkt['info']['data_bytes'][dbyte_pos : dbyte_pos + pkt_len]
                g_statistics_dict['total_pkt'] += 1

        rec_pkt_data(display_curr_idx, curr_node, invalid_pkt_cnt, d_str, g_pkt_rec_file)
        del_node_from_ring_link(g_dg_ring_link, curr_node)

        if g_display_from_1st_pkt:
            if display_curr_idx in idx_flag_marks.keys(): del idx_flag_marks[display_curr_idx]

            capt_idx += 1
            if capt_idx >= len(g_dg_ring_link['ctrl_blk']['ts_in_capt_ord']):
                #all pkts in pcapng and neighbouring lost pkt are processed. process the remaings.
                for rem_idx in idx_flag_marks.keys():
                    if in_round_range(rem_idx, start_idx, end_idx, g_dg_ring_link['capacity'], True, True):
                        g_statistics_dict['lost_pkt'] += 1
                        g_statistics_dict['total_pkt'] += 1
                        rec_pkt_data(rem_idx, None, 0, "", g_pkt_rec_file)
                break
            else:
                display_curr_idx = g_dg_ring_link['ctrl_blk']['ts_in_capt_ord'][capt_idx]
        else:
            if display_end_idx == display_curr_idx: break
            display_curr_idx = round_add(display_curr_idx, 1)

    g_dg_ring_link['ctrl_blk']['ts_in_capt_ord'].clear()
####################################################################################################

try:
    g_pkt_rec_file = open(g_output_file_name, "w")
    print("首包编号\t首包时间\t时间戳\t包数量\t有效包数量\t合并后数据\t包编号列表", file = g_pkt_rec_file)
except IOError:
    print("Open output file " + g_output_file_name + " error.")
    sys.exit(-1)

g_captured_pkts = pyshark.FileCapture(g_pacp_file_name, display_filter = g_pacp_display_filter, keep_packets = False)


g_dg_ring_link = init_ring_link(g_max_ts + 1)
g_dg_ring_link['ctrl_blk'] = dict(
        [
            ('start_ts', g_expect_start_ts),
            ('start_ts_node', None),
            ('first_pkt_time', 0),
            ('first_pkt_node', None),
            ('ts_in_capt_ord', [])
        ]
        )

g_is_first_pkt = True
while True:
    pkt = get_a_pkt(g_captured_pkts)
    if not(pkt['ret']):
        print("\nNo more pkts.\n")
        break

    sniff_t = pkt['sniff_time']
    sniff_t_str = sniff_t.strftime("%Y%m%d-%H:%M:%S.%f")
    ts = pkt['info']['ts']
    if not(ts in g_dg_ring_link['ctrl_blk']['ts_in_capt_ord']): 
        g_dg_ring_link['ctrl_blk']['ts_in_capt_ord'].append(ts)


    if g_is_first_pkt:
        g_dg_ring_link['ctrl_blk']['first_pkt_time'] = sniff_t

    #check ts overload
    if (g_ts_overload_period > 0) \
                and (sniff_t - g_dg_ring_link['ctrl_blk']['first_pkt_time'] > g_ts_overload_period_delta):
        refresh_stat()

    if not (ts in g_dg_ring_link['indices'].keys()):
        node = get_a_new_cust_node(ts, sniff_t)
        insert_node_into_ring_link(g_dg_ring_link, node)
    else:
        node = g_dg_ring_link['indices'][ts]

    node['data'].append(pkt)
    if g_is_first_pkt:
        g_dg_ring_link['ctrl_blk']['first_pkt_node'] = node
        g_is_first_pkt = False

refresh_stat()

print("", file = g_pkt_rec_file)
for k, v in g_statistics_dict.items(): 
    print(k + ": " + str(v))
    print(k + ": " + str(v), file = g_pkt_rec_file)

g_end_dt = datetime.datetime.now()
print_time_point(g_end_dt, "\n", " end process.")
print_elapsed_time(g_start_dt, g_end_dt, "\ntime elapsed: ", "", tgt = [g_pkt_rec_file, sys.stdout])
print("\n\n(" + g_app_name + " " + g_version + ")", file = g_pkt_rec_file)
print("\n\n(" + g_app_name + " " + g_version + ")")

g_pkt_rec_file.close()

if len(g_discarded_pkt_rec_dict['pkts']) > 0:
    disc_pkt_rec_f = open(g_discarded_pkt_rec_dict['fn'], "w")
    if(None == disc_pkt_rec_f):
        print("\n\nthere are some discared pkts, but open {} error, so output the contens to screen only...".
                format(g_discarded_pkt_rec_dict['fn']))
        disc_pkt_rec_f = sys.stdout

    #'header' : "|No.|ts|sniff_time|len|should_be_len|data|",
    print(g_discarded_pkt_rec_dict['header'], file = disc_pkt_rec_f)
    for pkt_list in g_discarded_pkt_rec_dict['pkts']:
        should_be_len = pkt_list['should_be_len']
        for pkt in pkt_list['data']:
            sn_time_str = pkt['sniff_time'].strftime("%Y%m%d-%H:%M:%S.%f")
            pkt_len = pkt['info']['payload_size'] - g_pkt_ele_pos_dict['ts'][1] #not including ts
            data_str = sep_hex_str(pkt['info']['data_bytes'], ' ')
            print("|{}|{:0{}}|{}|{}|{}|{}|".format(pkt['number'], pkt['info']['ts'], g_max_ts_digits,
                                                  sn_time_str, pkt_len, should_be_len, data_str),
                  file = disc_pkt_rec_f)
        print("", file = disc_pkt_rec_f)

    if(not(disc_pkt_rec_f is sys.stdout)): disc_pkt_rec_f.close()

print("\nFinished. Please check the result file: " + g_output_file_name)
