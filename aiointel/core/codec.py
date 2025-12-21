import msgspec


class TOML:
    encode = staticmethod(msgspec.toml.encode)
    decode = staticmethod(msgspec.toml.decode)

class JSON:
    encode = staticmethod(msgspec.json.encode)
    decode = staticmethod(msgspec.json.decode)

class Msgpack:
    encode = staticmethod(msgspec.msgpack.encode)
    decode = staticmethod(msgspec.msgpack.decode)

class YAML:
    encode = staticmethod(msgspec.yaml.encode)
    decode = staticmethod(msgspec.yaml.decode)
