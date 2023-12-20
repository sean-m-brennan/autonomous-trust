import { Message, Type, Field } from "protobufjs/light";

export const BinaryDataMsg = new Type("BinaryDataMsg")
    .add(new Field("event", 1, "string"))
    .add(new Field("elt_id", 2, "string"))
    .add(new Field("size", 3, "int32"))
    .add(new Field("data", 4, "bytes"));
