


typedef struct
{
  u8  digest_length;
  u8  key_length;
  u8  fanout;
  u8  depth;
  u32 leaf_length;
  u32 node_offset;
  u32 xof_length;
  u8  node_depth;
  u8  inner_length;
  u8  reserved[14];
  u8  salt[16];
  u8  personnel[16];

} blake2_params_t;

typedef struct
{
  u64 h[8];
  u64 t[2];
  u64 f[2];
  u32 buflen;
  u32 outlen;
  u8  last_node;

} blake2_state_t;

