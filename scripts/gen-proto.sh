#!/bin/bash
CURRENT_DIR=$1
PROTO_DIR=${CURRENT_DIR}/protos
OUT_DIR=${CURRENT_DIR}

echo "🧩 Protobuf fayllarni generatsiya qilinyapti..."

# genproto papkasini tozalash
rm -rf ${OUT_DIR}/genproto

# Barcha .proto fayllarni topib generatsiya qilish
find ${PROTO_DIR} -name "*.proto" | while read -r protofile; do
  echo "➡️  Generatsiya: $protofile"
  protoc -I=${PROTO_DIR} -I /usr/local/go --go_out=${OUT_DIR} --go-grpc_out=${OUT_DIR} "$protofile"
done

echo "✅ Barcha .proto fayllar muvaffaqiyatli generatsiya qilindi!"
