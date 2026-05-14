import ida_idaapi

from Assemport import Assemport


class AssemportPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    comment = "Assemport exports all functions separately in an assembly file."
    help = "Assemport exports all."
    wanted_name = "AssemportEx"

    def init(self):
        self.instance = Assemport()
        return self.instance


def PLUGIN_ENTRY():
    return AssemportPlugin()
