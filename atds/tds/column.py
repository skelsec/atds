

class CommonEqualityMixin(object):
    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self.__eq__(other)


class Column(CommonEqualityMixin):
    """
    Describes table column.  Can be used to define schema for bulk insert.

    Following flags can be used for columns in `flags` parameter:

    * :const:`.fNullable` - column can contain `NULL` values
    * :const:`.fCaseSen` - column is case-sensitive
    * :const:`.fReadWrite` - TODO document
    * :const:`.fIdentity` - TODO document
    * :const:`.fComputed` - TODO document

    :param name: Name of the column
    :type name: str
    :param type: Type of a column, e.g. :class:`pytds.tds_types.IntType`
    :param flags: Combination of flags for the column, multiple flags can be combined using binary or operator.
                  Possible flags are described above.
    """

    fNullable = 1
    fCaseSen = 2
    fReadWrite = 8
    fIdentity = 0x10
    fComputed = 0x20

    def __init__(self, name="", type=None, flags=fNullable, value=None):
        self.char_codec = None
        self.column_name = name
        self.column_usertype = 0
        self.flags = flags
        self.type = type
        self.value = value
        self.serializer = None

    def __repr__(self):
        val = self.value
        if isinstance(val, bytes) and len(self.value) > 100:
            val = self.value[:100] + b"... len is " + str(len(val)).encode("ascii")
        if isinstance(val, str) and len(self.value) > 100:
            val = self.value[:100] + "... len is " + str(len(val))
        return (
            "<Column(name={},type={},value={},flags={},user_type={},codec={})>".format(
                repr(self.column_name),
                repr(self.type),
                repr(val),
                repr(self.flags),
                repr(self.column_usertype),
                repr(self.char_codec),
            )
        )

    def choose_serializer(self, type_factory, collation):
        """
        Chooses appropriate data type serializer for column's data type.
        """
        return type_factory.serializer_by_type(sql_type=self.type, collation=collation)