
import idc 
import idautils  
import idaapi

def get_string(addr):
    out = ""
    while True:
        if Byte(addr) != 0:
            out += chr(Byte(addr))
        else:
            break
        addr += 1
    return out
  
class disp_func_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"

    help = "This is help"
    wanted_name = "Mark Dispatch Func"
    wanted_hotkey = "Ctrl-Alt-D"

    def init(self):
        ShowAbout()
        create_DISPFUNC_struct("DISP_FUNC")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        discern_DISPFUNC()

    def term(self):
        #idaapi.msg("Mark DISP_FUNC term() called!\n")
        pass

def PLUGIN_ENTRY():
    return disp_func_plugin_t()

def GetXrefNum(ea):
    count = 0
    for x in XrefsTo(ea, flags=0):
        count += 1
    
    return count    
 
def make_DispFun(ea):
    EaValue = Dword(ea)
    #print("Check 0x%X" % (ea) )
    if ( len(GetString(EaValue)) > 0 ):
        funcOffset = Dword(ea + 0x10)
        
        if ( len(Name(funcOffset)) > 0 ):
            #print("FindDISP_FUNC at 0x%X" % (ea) )
            strFuncName = GetString(EaValue)
            tmpName = strFuncName
            i = 0
            while (MakeNameEx(funcOffset, strFuncName, SN_NOWARN) == 0):
                strFuncName = "%s_%d" % (tmpName, i)
                i += 1
            
            for i in range(0, 8):
                MakeDword(ea+i*4)
            apply_struct(ea, "DISP_FUNC", -1)
            return 1
            
    return 0

    
# ###############################################   
def add_struct_to_idb(name):
    idc.Til2Idb(-1, name)
    
def find_or_create_struct(name):
    sid = idc.GetStrucIdByName(name)
    if (sid == idc.BADADDR):
        sid = idc.AddStrucEx(-1, name, 0)
        
    add_struct_to_idb(name) 
    
    return sid
    
    
def create_DISPFUNC_struct(name):
    sid = find_or_create_struct(name)
    idc.AddStrucMember(sid, "FuncName", 0, idc.FF_DWRD|FF_0OFF, -1, 4)
    idc.AddStrucMember(sid, "DISPID", 4, idc.FF_DWRD, -1, 4)
    idc.AddStrucMember(sid, "vtsParam", 8, idc.FF_DWRD, -1, 4)
    idc.AddStrucMember(sid, "vtRetVal", 0xC, idc.FF_DWRD, -1, 4)
    idc.AddStrucMember(sid, "pfnMember", 0x10, idc.FF_DWRD|FF_0OFF, -1, 4)
    idc.AddStrucMember(sid, "pfn", 0x14, idc.FF_DWRD|FF_0OFF, -1, 4)
    idc.AddStrucMember(sid, "filed18", 0x18, idc.FF_DWRD, -1, 4)
    idc.AddStrucMember(sid, "afxDispCustom", 0x1C, idc.FF_DWRD, -1, 4)
    
    return sid
    
def apply_struct(ea, name, size):
    sid = idc.GetStrucIdByName(name)
    if (size == -1):
        size = idc.GetStrucSize(sid)
        
    idc.MakeUnknown(ea, size, idc.DOUNK_DELNAMES)
    idaapi.doStruct(ea, size, sid)
    
    return size
    
def discern_DISPFUNC(): 
    curEa = ScreenEA()
    print "=================================="
    print("Start at %X" % (curEa) )
    ElmCount = 0
    while ( Dword(curEa) != 0 ):
        ret = make_DispFun(curEa)
        if (0 == ret ):
            break
        curEa += 0x20
        ElmCount += 1
    
    # last 0 struct
    if (ElmCount > 1):
        apply_struct(curEa, "DISP_FUNC", -1)
            
    print("Element count : %d" % (ElmCount+1))

def ShowAbout():
    print "=================================="
    print "By Snow  QQ:85703533"
    print "Mark IDispatch Automation function define."
    print "ShortCut : Ctrl+Alt+D\n"


  