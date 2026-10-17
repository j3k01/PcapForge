##! IEC 60870-5-104 logs from pcapforge's Spicy analyzer (iec104.spicy / iec104.evt):
##! iec104.log, one record per APDU (I, S or U frame), and iec104_command.log, one record per
##! command object (single / double / regulating step command, set point, interrogation,
##! counter interrogation). Names follow pcapforge's siem/iec104.jsonl.

module PcapforgeIEC104;

export {
	redef enum Log::ID += { LOG, COMMAND_LOG };

	type Info: record {
		ts: time &log;
		uid: string &log;
		id: conn_id &log;
		is_orig: bool &log;
		apci: string &log;                     ##< I, S or U
		u_function: string &log &optional;     ##< startdt_act, testfr_con, ... (U frames)
		send_seq: count &log &optional;        ##< N(S) (I frames)
		recv_seq: count &log &optional;        ##< N(R) (I and S frames)
		type_id: count &log &optional;
		type_name: string &log &optional;      ##< e.g. C_SC_NA_1
		category: string &log &optional;       ##< monitor, control, system, parameter, file
		cot: count &log &optional;
		cause: string &log &optional;          ##< e.g. activation, activation_con
		negative: bool &log &optional;
		test: bool &log &optional;
		originator: count &log &optional;
		common_address: count &log &optional;
		sq: bool &log &optional;
		num_objects: count &log &optional;
		ioa: vector of count &log &optional;   ##< information object addresses
	};

	type Command: record {
		ts: time &log;
		uid: string &log;
		id: conn_id &log;
		is_orig: bool &log;
		type_id: count &log;
		type_name: string &log;
		cot: count &log;
		cause: string &log;
		negative: bool &log;
		common_address: count &log;
		ioa: count &log;
		value: double &log;                    ##< SCS / DCS / RCS state, set point value, QOI or QCC request
		qualifier: count &log;                 ##< QU, QL or the QCC freeze bits
		select: bool &log;                     ##< S/E bit: select (true) or execute
	};

	global log_iec104: event(rec: Info);
	global log_iec104_command: event(rec: Command);
}

const types: table[count] of string = {
	[1] = "M_SP_NA_1", [2] = "M_SP_TA_1", [3] = "M_DP_NA_1", [4] = "M_DP_TA_1", [5] = "M_ST_NA_1",
	[6] = "M_ST_TA_1", [7] = "M_BO_NA_1", [8] = "M_BO_TA_1", [9] = "M_ME_NA_1", [10] = "M_ME_TA_1",
	[11] = "M_ME_NB_1", [12] = "M_ME_TB_1", [13] = "M_ME_NC_1", [14] = "M_ME_TC_1", [15] = "M_IT_NA_1",
	[16] = "M_IT_TA_1", [17] = "M_EP_TA_1", [18] = "M_EP_TB_1", [19] = "M_EP_TC_1", [20] = "M_PS_NA_1",
	[21] = "M_ME_ND_1", [30] = "M_SP_TB_1", [31] = "M_DP_TB_1", [32] = "M_ST_TB_1", [33] = "M_BO_TB_1",
	[34] = "M_ME_TD_1", [35] = "M_ME_TE_1", [36] = "M_ME_TF_1", [37] = "M_IT_TB_1", [38] = "M_EP_TD_1",
	[39] = "M_EP_TE_1", [40] = "M_EP_TF_1", [45] = "C_SC_NA_1", [46] = "C_DC_NA_1", [47] = "C_RC_NA_1",
	[48] = "C_SE_NA_1", [49] = "C_SE_NB_1", [50] = "C_SE_NC_1", [51] = "C_BO_NA_1", [58] = "C_SC_TA_1",
	[59] = "C_DC_TA_1", [60] = "C_RC_TA_1", [61] = "C_SE_TA_1", [62] = "C_SE_TB_1", [63] = "C_SE_TC_1",
	[64] = "C_BO_TA_1", [70] = "M_EI_NA_1", [100] = "C_IC_NA_1", [101] = "C_CI_NA_1", [102] = "C_RD_NA_1",
	[103] = "C_CS_NA_1", [104] = "C_TS_NA_1", [105] = "C_RP_NA_1", [106] = "C_CD_NA_1", [107] = "C_TS_TA_1",
	[110] = "P_ME_NA_1", [111] = "P_ME_NB_1", [112] = "P_ME_NC_1", [113] = "P_AC_NA_1", [120] = "F_FR_NA_1",
	[121] = "F_SR_NA_1", [122] = "F_SC_NA_1", [123] = "F_LS_NA_1", [124] = "F_AF_NA_1", [125] = "F_SG_NA_1",
	[126] = "F_DR_TA_1", [127] = "F_SC_NB_1",
} &default=function(t: count): string { return fmt("type_%d", t); };

const causes: table[count] of string = {
	[1] = "periodic", [2] = "background", [3] = "spontaneous", [4] = "initialized", [5] = "request",
	[6] = "activation", [7] = "activation_con", [8] = "deactivation", [9] = "deactivation_con",
	[10] = "activation_term", [11] = "return_remote", [12] = "return_local", [13] = "file_transfer",
	[20] = "interrogated_station", [37] = "requested_counter_general", [44] = "unknown_type",
	[45] = "unknown_cause", [46] = "unknown_common_address", [47] = "unknown_ioa",
} &default=function(c: count): string {
	if ( c > 20 && c <= 36 )
		return fmt("interrogated_group_%d", c - 20);
	if ( c > 37 && c <= 41 )
		return fmt("requested_counter_group_%d", c - 37);
	return fmt("cause_%d", c);
};

const u_functions: table[count] of string = {
	[0x01] = "startdt_act", [0x02] = "startdt_con", [0x04] = "stopdt_act", [0x08] = "stopdt_con",
	[0x10] = "testfr_act", [0x20] = "testfr_con",
} &default=function(f: count): string { return fmt("u_%d", f); };

function category(type_id: count): string
	{
	if ( type_id <= 44 || type_id == 70 )
		return "monitor";
	if ( type_id <= 69 )
		return "control";
	if ( type_id >= 100 && type_id <= 109 )
		return "system";
	if ( type_id >= 110 && type_id <= 119 )
		return "parameter";
	return "file";
	}

# ASDU header of the APDU being parsed, per connection direction (the asdu event precedes apdu).
global pending: table[string, bool] of Info;

# A connection seen from the middle (no SYN) is turned around so the RTU on 2404 is the responder,
# as Zeek does for its own analyzers' ports; otherwise the port-based analyzer would not attach.
redef likely_server_ports += { 2404/tcp };

# Content-based detection on other ports: STARTDT / TESTFR act answered by con.
@load-sigs ./dpd.sig

event zeek_init() &priority=5
	{
	Log::create_stream(PcapforgeIEC104::LOG, [$columns=Info, $ev=log_iec104, $path="iec104"]);
	Log::create_stream(PcapforgeIEC104::COMMAND_LOG, [$columns=Command, $ev=log_iec104_command, $path="iec104_command"]);
	}

event PcapforgeIEC104::asdu(c: connection, is_orig: bool, type_id: count, sq: bool, num: count, cot: count,
                            originator: count, common_address: count, ioas: vector of count)
	{
	pending[c$uid, is_orig] = Info($ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig, $apci="I",
	                               $type_id=type_id, $type_name=types[type_id], $category=category(type_id),
	                               $cot=cot & 0x3f, $cause=causes[cot & 0x3f], $negative=(cot & 0x40) != 0,
	                               $test=(cot & 0x80) != 0, $originator=originator,
	                               $common_address=common_address, $sq=sq, $num_objects=num, $ioa=ioas);
	}

event PcapforgeIEC104::apdu(c: connection, is_orig: bool, apci: string, u_function: count, send_seq: count,
                            recv_seq: count)
	{
	local info: Info;
	if ( apci == "I" && [c$uid, is_orig] in pending )
		{
		info = pending[c$uid, is_orig];
		delete pending[c$uid, is_orig];
		}
	else
		info = Info($ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig, $apci=apci);
	if ( apci == "I" )
		info$send_seq = send_seq;
	if ( apci != "U" )
		info$recv_seq = recv_seq;
	else
		info$u_function = u_functions[u_function];
	Log::write(PcapforgeIEC104::LOG, info);
	}

event PcapforgeIEC104::command(c: connection, is_orig: bool, type_id: count, cot: count, common_address: count,
                               ioa: count, value: double, qualifier: count, select: bool)
	{
	Log::write(PcapforgeIEC104::COMMAND_LOG, Command($ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
	           $type_id=type_id, $type_name=types[type_id], $cot=cot & 0x3f, $cause=causes[cot & 0x3f],
	           $negative=(cot & 0x40) != 0, $common_address=common_address, $ioa=ioa, $value=value,
	           $qualifier=qualifier, $select=select));
	}

event connection_state_remove(c: connection)
	{
	delete pending[c$uid, T];
	delete pending[c$uid, F];
	}
