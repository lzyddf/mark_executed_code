# -*- coding=utf-8 -*-

import time
import ida_dbg
from ida_dbg import *
from idaapi import *
import ida_ida
from ida_ida import *
import ida_pro
import ida_ua
from ida_allins import NN_callni, NN_call, NN_callfi
from ida_lines import generate_disasm_line, GENDSM_FORCE_CODE, GENDSM_REMOVE_TAGS
import ida_hexrays as hr
import ida_kernwin as kw
import ida_funcs
import idautils
from idautils import *
from idc import *

PLUGIN_NAME = 'mark executed code'

ID_CLEAR_COLOR = '%s:clear' % PLUGIN_NAME

default_color = 0xFFFFFFFF
func_color = 0x98FF98
item_color = 0xffe699
hint_color = 0x98FF98

func_pseudocode_info_list = {}

class hexrays_hooks_t(hr.Hexrays_Hooks):
    def __init__(self):
        hr.Hexrays_Hooks.__init__(self)

    def text_ready(self, vu):
        vu.del_orphan_cmts()
        func_entry_ea = vu.cfunc.entry_ea
        if func_entry_ea in func_pseudocode_info_list:
            pc = vu.cfunc.get_pseudocode()
            for i in func_pseudocode_info_list[func_entry_ea]:
                pc[i].bgcolor = item_color
        return 0
        
    def populating_popup(self, widget, popup_handle, vu):
        kw.attach_action_to_popup(vu.ct, None, ID_CLEAR_COLOR, PLUGIN_NAME+"/")
        return 0
        
class dbg_hooks_t(ida_dbg.DBG_Hooks):
    def __init__(self):
        ida_dbg.DBG_Hooks.__init__(self)
        
    def _set_pseudocode_cmt(self, vu, ea, cmt):
        commentSet = False
        eamap = vu.cfunc.get_eamap()
        tl = treeloc_t()
        tl.ea = eamap[ea][0].ea
        tl.itp = ITP_SEMI
        vu.cfunc.set_user_cmt(tl, cmt)
        vu.cfunc.save_user_cmts()

        for itp in [ITP_SEMI, ITP_BRACE2]:
            tl.itp = itp
            vu.cfunc.set_user_cmt(tl, cmt)
            if vu.cfunc.get_user_cmt(tl, RETRIEVE_ONCE) != None:
                commentSet = True
                break
        vu.cfunc.del_orphan_cmts()
        vu.cfunc.save_user_cmts()
        if not commentSet:
            print ("pseudo comment error at %08x" % ea)
        else:
            vu.refresh_ctext()
        
    def _get_operand_value(self, ea, n):
        insn = ida_ua.insn_t()
        inslen = ida_ua.decode_insn(insn, ea)
        if inslen == 0:
            return None
        op = insn.ops[n]
        if not op:
            return None

        if op.type in [ ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near, ida_ua.o_displ ]:
            value = op.addr
        elif op.type == ida_ua.o_reg:
            value = get_reg_value(print_operand(ea, 0))
        elif op.type == ida_ua.o_imm:
            value = op.value
        elif op.type == ida_ua.o_phrase:
            value = op.phrase
        else:
            value = None
            
        return value;
        
    #-------------------------------------------
    #This code is referenced from 'https://github.com/patois'
    #-------------------------------------------
    def _get_item_ea_list(self, vu, line):
        indexes = []
        ea_list = []
        tag = COLOR_ON + chr(COLOR_ADDR)
        pos = line.find(tag)
        cur_col = pos+len(tag)
        while pos != -1 and len(line[cur_col:]) >= COLOR_ADDR_SIZE:
            addr = line[cur_col:cur_col+COLOR_ADDR_SIZE]
            idx = int(addr, 16)
            ca = ctree_anchor_t()
            ca.value = idx
            if ca.is_valid_anchor() and ca.is_citem_anchor() and idx not in indexes:
                indexes.append(idx)
            pos = line.find(tag, cur_col+COLOR_ADDR_SIZE)
            cur_col = pos+len(tag)
            
        for idx in indexes:
            item = vu.cfunc.treeitems.at(idx)
            if item and item.ea != BADADDR and item.ea not in ea_list:
                ea_list.append(item.ea)
                
        return sorted(ea_list)
    #-------------------------------------------

    def dbg_suspend_process(self):
        set_color(get_event_ea(), CIC_ITEM, item_color)

        vu = hr.get_widget_vdui(kw.get_current_widget())
        if not vu: return

        func_entry_ea = vu.cfunc.entry_ea
        if func_entry_ea not in func_pseudocode_info_list:
            func_pseudocode_info_list[func_entry_ea] = []
            func = ida_funcs.get_func(func_entry_ea)
            if func and func.flags & (FUNC_THUNK | FUNC_LIB) == 0:
                func.color = func_color #set func color

        lineno = vu.cpos.lnnum  #get curpos line
        if lineno <= 0: return
            
        if lineno not in func_pseudocode_info_list[func_entry_ea]:
            func_pseudocode_info_list[func_entry_ea].append(lineno) #record new line
        
        pc = vu.cfunc.get_pseudocode()
        pc[lineno].bgcolor = item_color #set pc color
        vu.refresh_ctext()
        
        ea_list = self._get_item_ea_list(vu, pc[lineno].line)
        #print(','.join('{:#x}'.format(x) for x in ea_list))
        if not ea_list: return

        arg_list = []
        for ea in ea_list:
            set_color(ea, CIC_ITEM, item_color) 
            arg_addr_list = get_arg_addrs(ea)
            if arg_addr_list:
                for arg_addr in arg_addr_list:
                    arg_value = self._get_operand_value(arg_addr, 0)
                    if arg_value != None:
                        arg_value = arg_list.append(arg_value)
            #print(','.join('{:#x}'.format(x) for x in arg_list))
            if arg_list:
                cmt = 'arg: ' + ', '.join('{:#x}'.format(x) for x in arg_list)
                self._set_pseudocode_cmt(vu, ea, cmt)   # set comment
                arg_list.clear()
                break

class mark_t():
    hr_hexrays_hooks = None
    dbg_hooks = None
    
    def __init__(self):
        self.hr_hexrays_hooks = hexrays_hooks_t()
        self.hr_hexrays_hooks.hook()

        self.dbg_hooks = dbg_hooks_t()
        self.dbg_hooks.hook()
        
    def close(self):
        self.hr_hexrays_hooks.unhook()
        del self.hr_hexrays_hooks
        
        self.dbg_hooks.unhook()
        del self.dbg_hooks
                
class clear_color_t(kw.action_handler_t):
    def __init__(self):
        kw.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        for func_addr in func_pseudocode_info_list.keys():
            set_color(func_addr, CIC_FUNC, default_color)
            func = get_func(func_addr)
            for addr in range(func.start_ea, func.end_ea):
                set_color(addr, CIC_ITEM, default_color)

        func_pseudocode_info_list.clear()
        open_pseudocode(ctx.cur_ea, OPF_NO_WAIT)
        
    def update(self, ctx):
        return kw.AST_ENABLE_FOR_WIDGET if \
            ctx.widget_type == kw.BWN_PSEUDOCODE else \
            kw.AST_DISABLE_FOR_WIDGET
    
class mark_executed_code_t(ida_idaapi.plugin_t):

    help = ''
    comment = ''

    wanted_name = PLUGIN_NAME
    wanted_hotkey = 'Ctrl-Shift-M'

    flags = PLUGIN_MOD
    
    mark = None

    def init(self):
        if not hr.init_hexrays_plugin():
            return PLUGIN_SKIP
        
        kw.register_action(
            kw.action_desc_t(
                ID_CLEAR_COLOR,
                "clear all colors",
                clear_color_t(),
                None))
        
        print('[+]mark_executed_code load')

        if not self.mark:
            self.mark = mark_t()
            print('[+]mark_executed_code on')

        return PLUGIN_KEEP
        
    def run(self, arg):
        if not self.mark:
            self.mark = mark_t()
            print('[+]mark_executed_code on')
        else:
            self.mark.close()
            del self.mark
            kw.unregister_action(ID_CLEAR_COLOR)
            print('[+]mark_executed_code off')
        
    def term(self):
        if self.mark:
            self.mark.close()
            del self.mark
            kw.unregister_action(ID_CLEAR_COLOR)
            print('[+]mark_executed_code off')
        
        print('[+]mark_executed_code unload')

def PLUGIN_ENTRY():
    return mark_executed_code_t()