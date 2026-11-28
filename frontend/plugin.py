import ida_idaapi
import ida_kernwin


class FrinetHeadlessPlugin(ida_idaapi.plugin_t):
    """ Headless plugin stub """

    flags = ida_idaapi.PLUGIN_HIDE
    comment: str = "Frinet trace explorer"
    wanted_name: str = "Frinet"

    def init(self) -> int:
        return ida_idaapi.PLUGIN_SKIP


def PLUGIN_ENTRY() -> ida_idaapi.plugin_t:
    if not ida_kernwin.is_idaq():
        return FrinetHeadlessPlugin()

    from frinet_ida.plugin import FrinetIDAPlugin
    return FrinetIDAPlugin()
