#pragma once
/**
* salt types
*/
typedef enum SALT_TYPE_ {
  SALT_TYPE_INVALID = 0,
  SALT_TYPE_NONE = 1,
  SALT_TYPE_EMBEDDED = 2,
  SALT_TYPE_INTERN = 3,
  SALT_TYPE_EXTERN = 4,
  SALT_TYPE_VIRTUAL = 5
} SALT_TYPE;
