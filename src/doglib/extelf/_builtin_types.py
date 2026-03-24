from ._cheader import CHeader

class CTypes(CHeader):
    def __init__(self, bits=None):
        from importlib.resources import files
        header_src = files('doglib.data.extelf').joinpath('ctypes_builtin.h')
        super().__init__(str(header_src), bits=bits)
