import pyshark
import datetime
from datetime import timedelta
import sys
import os

usage_str = "usage: " + os.path.basename(__file__) + " pacp-file-name [out-put-file-name]"
if len(sys.argv) != 2 and len(sys.argv) != 3:
    print(usage_str)
    sys.exit(0)
g_pacp_file_name = sys.argv[1]
g_output_file_name = "data_groups.txt" if len(sys.argv) !=3 else sys.argv[2]
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
    ret = {'ret' : False}
    while True:
        try:
            udp_pkt = cap.next()
            ds = str(udp_pkt.data.data)
            if(ds[g_pkt_ele_pos_dict['cmd'][0] :  g_pkt_ele_pos_dict['cmd'][0] + g_pkt_ele_pos_dict['cmd'][1]] 
                         == g_cmd_bytes_str):
                ret['ret'] = True
                ret['sniff_time'] = udp_pkt.sniff_time
                ret['info'] = dict()
                for k in g_pkt_ele_pos_dict.keys():
                    ret['info'][k] \
                        = eval("0x" + ds[g_pkt_ele_pos_dict[k][0] : g_pkt_ele_pos_dict[k][0] + g_pkt_ele_pos_dict[k][1]]) 
                return ret
        except StopIteration:
            break;
    return ret

g_statistics_dict = \
{
    'total_pkt' : 0,
    'total_dg' : 0,
    'good_dg' : 0,
    'bad_dg' : 0,
}
def record_data_group(good, d_g, rec_file):
    min_dt_s = d_g['min_sniff_time'].strftime("%Y%m%d-%H:%M:%S.%f")
    max_dt_s = d_g['max_sniff_time'].strftime("%Y%m%d-%H:%M:%S.%f")
    t_delta = d_g['max_sniff_time'] - d_g['min_sniff_time']
    print(str(d_g['ts']) + "\t", file = rec_file, end = "")
    print(min_dt_s + "\t" + max_dt_s + "\t", file = rec_file, end = "")
    t_delta_us = t_delta.seconds * 1000000 + t_delta.microseconds
    print(str(t_delta_us) + "\t\t", file = rec_file, end = "")
    if(good):
        print("good\t", file = rec_file, end = "")
        g_statistics_dict['good_dg'] += 1
        g_statistics_dict['total_pkt'] += d_g['pkt_cnt_per_line']
    else:
        print("bad\t\t", file = rec_file, end = "")
        print('-'.join(map(str, d_g['pkt_no'])) + "\t", file = rec_file, end = "")
        g_statistics_dict['bad_dg'] += 1
        g_statistics_dict['total_pkt'] += len(d_g['pkt_no'])

    g_statistics_dict['total_dg'] += 1
    print("", file = rec_file)

def count_a_new_pkt(data_group, pkt_info):
    data_group['ts'] = pkt_info['info']['ts']
    data_group['pkt_cnt_per_line'] = pkt_info['info']['pkt_cnt_per_line']
    data_group['pkt_no'] = [pkt_info['info']['pkt_no']]
    data_group['min_sniff_time'] = pkt_info['sniff_time']
    data_group['max_sniff_time'] = pkt_info['sniff_time']

try:
    g_data_group_file = open(g_output_file_name, "w")
    print("时间戳\t最小时间\t\t\t最大时间\t\t\t时间差(us)\t是否完整\t包序号", file = g_data_group_file)
except IOError:
    print("Open output file " + g_output_file_name + " error.")
    sys.exit(-1)

g_captured_pkts = pyshark.FileCapture(g_pacp_file_name, display_filter=g_pacp_display_filter, keep_packets = False)

g_ts_repeat_times_delta = timedelta(0, 52) #52 seconds

g_start_dt = datetime.datetime.now()
print(g_start_dt.strftime("%Y%m%d-%H:%M:%S.%f") + " start process")
print("\nprocessing...\n")


g_stat_dict = {}
g_fluch_cnt = 10 * 15
g_cnt_idx = 0
while True:
    ret = get_a_pkt(g_captured_pkts)
    if not(ret['ret']):
        print("\nNo more pkts.\n")
        break

    """
    print(ret['sniff_time'].strftime("%H:%M:%S.%f") + "\t", end = "")
    for k in ret['info'].keys():
        print(str(ret['info'][k]) + "|", end = "")
    print("")
    """

    ts = ret['info']['ts']
    if ts not in g_stat_dict.keys():
        g_stat_dict[ts] = dict({})
        count_a_new_pkt(g_stat_dict[ts], ret)
    else:
        times_delta = ret['sniff_time'] - g_stat_dict[ts]['min_sniff_time'] 
        if times_delta <= g_ts_repeat_times_delta:
            g_stat_dict[ts]['pkt_no'].append(ret['info']['pkt_no'])
            if(ret['sniff_time'] < g_stat_dict[ts]['min_sniff_time']):
                g_stat_dict[ts]['min_sniff_time'] = ret['sniff_time']
            if(ret['sniff_time'] > g_stat_dict[ts]['max_sniff_time']):
                g_stat_dict[ts]['max_sniff_time'] = ret['sniff_time']
            if(len(g_stat_dict[ts]['pkt_no']) >= g_stat_dict[ts]['pkt_cnt_per_line']):
                #a good data group
                record_data_group(True, g_stat_dict[ts], g_data_group_file)
                del g_stat_dict[ts]
        else:
            #a bad data group
            record_data_group(False, g_stat_dict[ts], g_data_group_file)
            g_stat_dict[ts] = dict({})
            count_a_new_pkt(g_stat_dict[ts], ret)
    g_cnt_idx += 1
    if g_cnt_idx >= g_fluch_cnt:
        g_data_group_file.flush()
        g_cnt_idx = 0

#if there are remaining pkts, they are all bad.
for k, v in g_stat_dict.items():
    record_data_group(False, v, g_data_group_file)

print("", file = g_data_group_file)
for k, v in g_statistics_dict.items(): 
    print(k + ":" + str(v))
    print(k + ":" + str(v), file = g_data_group_file)
bad_dg_ratio = 0 if 0 == g_statistics_dict['total_dg'] \
                else g_statistics_dict['bad_dg']/float(g_statistics_dict['total_dg'])
bg_dg_r_s = "bad data group ration: {:.2%}".format(bad_dg_ratio)
print("\n" + bg_dg_r_s , file = g_data_group_file)
print("\n" + bg_dg_r_s)

g_data_group_file.close()

g_end_dt = datetime.datetime.now()
print(g_end_dt.strftime("\n%Y%m%d-%H:%M:%S.%f") + " end process.")
g_used_time_dura = g_end_dt - g_start_dt
print("time elapsed: {} days, {} seconds, {} us".format(g_used_time_dura.days, g_used_time_dura.seconds,  g_used_time_dura.microseconds))

print("\nFinished. Please check the result file: " + g_output_file_name)
