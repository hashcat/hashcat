/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define _SHA1_

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

typedef struct
{
  u32 dec;
  u32 len;

} entry_t;

__constant entry_t pc[1024] =
{
  { 0x00000030, 1 },
  { 0x00000031, 1 },
  { 0x00000032, 1 },
  { 0x00000033, 1 },
  { 0x00000034, 1 },
  { 0x00000035, 1 },
  { 0x00000036, 1 },
  { 0x00000037, 1 },
  { 0x00000038, 1 },
  { 0x00000039, 1 },
  { 0x00003031, 2 },
  { 0x00003131, 2 },
  { 0x00003231, 2 },
  { 0x00003331, 2 },
  { 0x00003431, 2 },
  { 0x00003531, 2 },
  { 0x00003631, 2 },
  { 0x00003731, 2 },
  { 0x00003831, 2 },
  { 0x00003931, 2 },
  { 0x00003032, 2 },
  { 0x00003132, 2 },
  { 0x00003232, 2 },
  { 0x00003332, 2 },
  { 0x00003432, 2 },
  { 0x00003532, 2 },
  { 0x00003632, 2 },
  { 0x00003732, 2 },
  { 0x00003832, 2 },
  { 0x00003932, 2 },
  { 0x00003033, 2 },
  { 0x00003133, 2 },
  { 0x00003233, 2 },
  { 0x00003333, 2 },
  { 0x00003433, 2 },
  { 0x00003533, 2 },
  { 0x00003633, 2 },
  { 0x00003733, 2 },
  { 0x00003833, 2 },
  { 0x00003933, 2 },
  { 0x00003034, 2 },
  { 0x00003134, 2 },
  { 0x00003234, 2 },
  { 0x00003334, 2 },
  { 0x00003434, 2 },
  { 0x00003534, 2 },
  { 0x00003634, 2 },
  { 0x00003734, 2 },
  { 0x00003834, 2 },
  { 0x00003934, 2 },
  { 0x00003035, 2 },
  { 0x00003135, 2 },
  { 0x00003235, 2 },
  { 0x00003335, 2 },
  { 0x00003435, 2 },
  { 0x00003535, 2 },
  { 0x00003635, 2 },
  { 0x00003735, 2 },
  { 0x00003835, 2 },
  { 0x00003935, 2 },
  { 0x00003036, 2 },
  { 0x00003136, 2 },
  { 0x00003236, 2 },
  { 0x00003336, 2 },
  { 0x00003436, 2 },
  { 0x00003536, 2 },
  { 0x00003636, 2 },
  { 0x00003736, 2 },
  { 0x00003836, 2 },
  { 0x00003936, 2 },
  { 0x00003037, 2 },
  { 0x00003137, 2 },
  { 0x00003237, 2 },
  { 0x00003337, 2 },
  { 0x00003437, 2 },
  { 0x00003537, 2 },
  { 0x00003637, 2 },
  { 0x00003737, 2 },
  { 0x00003837, 2 },
  { 0x00003937, 2 },
  { 0x00003038, 2 },
  { 0x00003138, 2 },
  { 0x00003238, 2 },
  { 0x00003338, 2 },
  { 0x00003438, 2 },
  { 0x00003538, 2 },
  { 0x00003638, 2 },
  { 0x00003738, 2 },
  { 0x00003838, 2 },
  { 0x00003938, 2 },
  { 0x00003039, 2 },
  { 0x00003139, 2 },
  { 0x00003239, 2 },
  { 0x00003339, 2 },
  { 0x00003439, 2 },
  { 0x00003539, 2 },
  { 0x00003639, 2 },
  { 0x00003739, 2 },
  { 0x00003839, 2 },
  { 0x00003939, 2 },
  { 0x00303031, 3 },
  { 0x00313031, 3 },
  { 0x00323031, 3 },
  { 0x00333031, 3 },
  { 0x00343031, 3 },
  { 0x00353031, 3 },
  { 0x00363031, 3 },
  { 0x00373031, 3 },
  { 0x00383031, 3 },
  { 0x00393031, 3 },
  { 0x00303131, 3 },
  { 0x00313131, 3 },
  { 0x00323131, 3 },
  { 0x00333131, 3 },
  { 0x00343131, 3 },
  { 0x00353131, 3 },
  { 0x00363131, 3 },
  { 0x00373131, 3 },
  { 0x00383131, 3 },
  { 0x00393131, 3 },
  { 0x00303231, 3 },
  { 0x00313231, 3 },
  { 0x00323231, 3 },
  { 0x00333231, 3 },
  { 0x00343231, 3 },
  { 0x00353231, 3 },
  { 0x00363231, 3 },
  { 0x00373231, 3 },
  { 0x00383231, 3 },
  { 0x00393231, 3 },
  { 0x00303331, 3 },
  { 0x00313331, 3 },
  { 0x00323331, 3 },
  { 0x00333331, 3 },
  { 0x00343331, 3 },
  { 0x00353331, 3 },
  { 0x00363331, 3 },
  { 0x00373331, 3 },
  { 0x00383331, 3 },
  { 0x00393331, 3 },
  { 0x00303431, 3 },
  { 0x00313431, 3 },
  { 0x00323431, 3 },
  { 0x00333431, 3 },
  { 0x00343431, 3 },
  { 0x00353431, 3 },
  { 0x00363431, 3 },
  { 0x00373431, 3 },
  { 0x00383431, 3 },
  { 0x00393431, 3 },
  { 0x00303531, 3 },
  { 0x00313531, 3 },
  { 0x00323531, 3 },
  { 0x00333531, 3 },
  { 0x00343531, 3 },
  { 0x00353531, 3 },
  { 0x00363531, 3 },
  { 0x00373531, 3 },
  { 0x00383531, 3 },
  { 0x00393531, 3 },
  { 0x00303631, 3 },
  { 0x00313631, 3 },
  { 0x00323631, 3 },
  { 0x00333631, 3 },
  { 0x00343631, 3 },
  { 0x00353631, 3 },
  { 0x00363631, 3 },
  { 0x00373631, 3 },
  { 0x00383631, 3 },
  { 0x00393631, 3 },
  { 0x00303731, 3 },
  { 0x00313731, 3 },
  { 0x00323731, 3 },
  { 0x00333731, 3 },
  { 0x00343731, 3 },
  { 0x00353731, 3 },
  { 0x00363731, 3 },
  { 0x00373731, 3 },
  { 0x00383731, 3 },
  { 0x00393731, 3 },
  { 0x00303831, 3 },
  { 0x00313831, 3 },
  { 0x00323831, 3 },
  { 0x00333831, 3 },
  { 0x00343831, 3 },
  { 0x00353831, 3 },
  { 0x00363831, 3 },
  { 0x00373831, 3 },
  { 0x00383831, 3 },
  { 0x00393831, 3 },
  { 0x00303931, 3 },
  { 0x00313931, 3 },
  { 0x00323931, 3 },
  { 0x00333931, 3 },
  { 0x00343931, 3 },
  { 0x00353931, 3 },
  { 0x00363931, 3 },
  { 0x00373931, 3 },
  { 0x00383931, 3 },
  { 0x00393931, 3 },
  { 0x00303032, 3 },
  { 0x00313032, 3 },
  { 0x00323032, 3 },
  { 0x00333032, 3 },
  { 0x00343032, 3 },
  { 0x00353032, 3 },
  { 0x00363032, 3 },
  { 0x00373032, 3 },
  { 0x00383032, 3 },
  { 0x00393032, 3 },
  { 0x00303132, 3 },
  { 0x00313132, 3 },
  { 0x00323132, 3 },
  { 0x00333132, 3 },
  { 0x00343132, 3 },
  { 0x00353132, 3 },
  { 0x00363132, 3 },
  { 0x00373132, 3 },
  { 0x00383132, 3 },
  { 0x00393132, 3 },
  { 0x00303232, 3 },
  { 0x00313232, 3 },
  { 0x00323232, 3 },
  { 0x00333232, 3 },
  { 0x00343232, 3 },
  { 0x00353232, 3 },
  { 0x00363232, 3 },
  { 0x00373232, 3 },
  { 0x00383232, 3 },
  { 0x00393232, 3 },
  { 0x00303332, 3 },
  { 0x00313332, 3 },
  { 0x00323332, 3 },
  { 0x00333332, 3 },
  { 0x00343332, 3 },
  { 0x00353332, 3 },
  { 0x00363332, 3 },
  { 0x00373332, 3 },
  { 0x00383332, 3 },
  { 0x00393332, 3 },
  { 0x00303432, 3 },
  { 0x00313432, 3 },
  { 0x00323432, 3 },
  { 0x00333432, 3 },
  { 0x00343432, 3 },
  { 0x00353432, 3 },
  { 0x00363432, 3 },
  { 0x00373432, 3 },
  { 0x00383432, 3 },
  { 0x00393432, 3 },
  { 0x00303532, 3 },
  { 0x00313532, 3 },
  { 0x00323532, 3 },
  { 0x00333532, 3 },
  { 0x00343532, 3 },
  { 0x00353532, 3 },
  { 0x00363532, 3 },
  { 0x00373532, 3 },
  { 0x00383532, 3 },
  { 0x00393532, 3 },
  { 0x00303632, 3 },
  { 0x00313632, 3 },
  { 0x00323632, 3 },
  { 0x00333632, 3 },
  { 0x00343632, 3 },
  { 0x00353632, 3 },
  { 0x00363632, 3 },
  { 0x00373632, 3 },
  { 0x00383632, 3 },
  { 0x00393632, 3 },
  { 0x00303732, 3 },
  { 0x00313732, 3 },
  { 0x00323732, 3 },
  { 0x00333732, 3 },
  { 0x00343732, 3 },
  { 0x00353732, 3 },
  { 0x00363732, 3 },
  { 0x00373732, 3 },
  { 0x00383732, 3 },
  { 0x00393732, 3 },
  { 0x00303832, 3 },
  { 0x00313832, 3 },
  { 0x00323832, 3 },
  { 0x00333832, 3 },
  { 0x00343832, 3 },
  { 0x00353832, 3 },
  { 0x00363832, 3 },
  { 0x00373832, 3 },
  { 0x00383832, 3 },
  { 0x00393832, 3 },
  { 0x00303932, 3 },
  { 0x00313932, 3 },
  { 0x00323932, 3 },
  { 0x00333932, 3 },
  { 0x00343932, 3 },
  { 0x00353932, 3 },
  { 0x00363932, 3 },
  { 0x00373932, 3 },
  { 0x00383932, 3 },
  { 0x00393932, 3 },
  { 0x00303033, 3 },
  { 0x00313033, 3 },
  { 0x00323033, 3 },
  { 0x00333033, 3 },
  { 0x00343033, 3 },
  { 0x00353033, 3 },
  { 0x00363033, 3 },
  { 0x00373033, 3 },
  { 0x00383033, 3 },
  { 0x00393033, 3 },
  { 0x00303133, 3 },
  { 0x00313133, 3 },
  { 0x00323133, 3 },
  { 0x00333133, 3 },
  { 0x00343133, 3 },
  { 0x00353133, 3 },
  { 0x00363133, 3 },
  { 0x00373133, 3 },
  { 0x00383133, 3 },
  { 0x00393133, 3 },
  { 0x00303233, 3 },
  { 0x00313233, 3 },
  { 0x00323233, 3 },
  { 0x00333233, 3 },
  { 0x00343233, 3 },
  { 0x00353233, 3 },
  { 0x00363233, 3 },
  { 0x00373233, 3 },
  { 0x00383233, 3 },
  { 0x00393233, 3 },
  { 0x00303333, 3 },
  { 0x00313333, 3 },
  { 0x00323333, 3 },
  { 0x00333333, 3 },
  { 0x00343333, 3 },
  { 0x00353333, 3 },
  { 0x00363333, 3 },
  { 0x00373333, 3 },
  { 0x00383333, 3 },
  { 0x00393333, 3 },
  { 0x00303433, 3 },
  { 0x00313433, 3 },
  { 0x00323433, 3 },
  { 0x00333433, 3 },
  { 0x00343433, 3 },
  { 0x00353433, 3 },
  { 0x00363433, 3 },
  { 0x00373433, 3 },
  { 0x00383433, 3 },
  { 0x00393433, 3 },
  { 0x00303533, 3 },
  { 0x00313533, 3 },
  { 0x00323533, 3 },
  { 0x00333533, 3 },
  { 0x00343533, 3 },
  { 0x00353533, 3 },
  { 0x00363533, 3 },
  { 0x00373533, 3 },
  { 0x00383533, 3 },
  { 0x00393533, 3 },
  { 0x00303633, 3 },
  { 0x00313633, 3 },
  { 0x00323633, 3 },
  { 0x00333633, 3 },
  { 0x00343633, 3 },
  { 0x00353633, 3 },
  { 0x00363633, 3 },
  { 0x00373633, 3 },
  { 0x00383633, 3 },
  { 0x00393633, 3 },
  { 0x00303733, 3 },
  { 0x00313733, 3 },
  { 0x00323733, 3 },
  { 0x00333733, 3 },
  { 0x00343733, 3 },
  { 0x00353733, 3 },
  { 0x00363733, 3 },
  { 0x00373733, 3 },
  { 0x00383733, 3 },
  { 0x00393733, 3 },
  { 0x00303833, 3 },
  { 0x00313833, 3 },
  { 0x00323833, 3 },
  { 0x00333833, 3 },
  { 0x00343833, 3 },
  { 0x00353833, 3 },
  { 0x00363833, 3 },
  { 0x00373833, 3 },
  { 0x00383833, 3 },
  { 0x00393833, 3 },
  { 0x00303933, 3 },
  { 0x00313933, 3 },
  { 0x00323933, 3 },
  { 0x00333933, 3 },
  { 0x00343933, 3 },
  { 0x00353933, 3 },
  { 0x00363933, 3 },
  { 0x00373933, 3 },
  { 0x00383933, 3 },
  { 0x00393933, 3 },
  { 0x00303034, 3 },
  { 0x00313034, 3 },
  { 0x00323034, 3 },
  { 0x00333034, 3 },
  { 0x00343034, 3 },
  { 0x00353034, 3 },
  { 0x00363034, 3 },
  { 0x00373034, 3 },
  { 0x00383034, 3 },
  { 0x00393034, 3 },
  { 0x00303134, 3 },
  { 0x00313134, 3 },
  { 0x00323134, 3 },
  { 0x00333134, 3 },
  { 0x00343134, 3 },
  { 0x00353134, 3 },
  { 0x00363134, 3 },
  { 0x00373134, 3 },
  { 0x00383134, 3 },
  { 0x00393134, 3 },
  { 0x00303234, 3 },
  { 0x00313234, 3 },
  { 0x00323234, 3 },
  { 0x00333234, 3 },
  { 0x00343234, 3 },
  { 0x00353234, 3 },
  { 0x00363234, 3 },
  { 0x00373234, 3 },
  { 0x00383234, 3 },
  { 0x00393234, 3 },
  { 0x00303334, 3 },
  { 0x00313334, 3 },
  { 0x00323334, 3 },
  { 0x00333334, 3 },
  { 0x00343334, 3 },
  { 0x00353334, 3 },
  { 0x00363334, 3 },
  { 0x00373334, 3 },
  { 0x00383334, 3 },
  { 0x00393334, 3 },
  { 0x00303434, 3 },
  { 0x00313434, 3 },
  { 0x00323434, 3 },
  { 0x00333434, 3 },
  { 0x00343434, 3 },
  { 0x00353434, 3 },
  { 0x00363434, 3 },
  { 0x00373434, 3 },
  { 0x00383434, 3 },
  { 0x00393434, 3 },
  { 0x00303534, 3 },
  { 0x00313534, 3 },
  { 0x00323534, 3 },
  { 0x00333534, 3 },
  { 0x00343534, 3 },
  { 0x00353534, 3 },
  { 0x00363534, 3 },
  { 0x00373534, 3 },
  { 0x00383534, 3 },
  { 0x00393534, 3 },
  { 0x00303634, 3 },
  { 0x00313634, 3 },
  { 0x00323634, 3 },
  { 0x00333634, 3 },
  { 0x00343634, 3 },
  { 0x00353634, 3 },
  { 0x00363634, 3 },
  { 0x00373634, 3 },
  { 0x00383634, 3 },
  { 0x00393634, 3 },
  { 0x00303734, 3 },
  { 0x00313734, 3 },
  { 0x00323734, 3 },
  { 0x00333734, 3 },
  { 0x00343734, 3 },
  { 0x00353734, 3 },
  { 0x00363734, 3 },
  { 0x00373734, 3 },
  { 0x00383734, 3 },
  { 0x00393734, 3 },
  { 0x00303834, 3 },
  { 0x00313834, 3 },
  { 0x00323834, 3 },
  { 0x00333834, 3 },
  { 0x00343834, 3 },
  { 0x00353834, 3 },
  { 0x00363834, 3 },
  { 0x00373834, 3 },
  { 0x00383834, 3 },
  { 0x00393834, 3 },
  { 0x00303934, 3 },
  { 0x00313934, 3 },
  { 0x00323934, 3 },
  { 0x00333934, 3 },
  { 0x00343934, 3 },
  { 0x00353934, 3 },
  { 0x00363934, 3 },
  { 0x00373934, 3 },
  { 0x00383934, 3 },
  { 0x00393934, 3 },
  { 0x00303035, 3 },
  { 0x00313035, 3 },
  { 0x00323035, 3 },
  { 0x00333035, 3 },
  { 0x00343035, 3 },
  { 0x00353035, 3 },
  { 0x00363035, 3 },
  { 0x00373035, 3 },
  { 0x00383035, 3 },
  { 0x00393035, 3 },
  { 0x00303135, 3 },
  { 0x00313135, 3 },
  { 0x00323135, 3 },
  { 0x00333135, 3 },
  { 0x00343135, 3 },
  { 0x00353135, 3 },
  { 0x00363135, 3 },
  { 0x00373135, 3 },
  { 0x00383135, 3 },
  { 0x00393135, 3 },
  { 0x00303235, 3 },
  { 0x00313235, 3 },
  { 0x00323235, 3 },
  { 0x00333235, 3 },
  { 0x00343235, 3 },
  { 0x00353235, 3 },
  { 0x00363235, 3 },
  { 0x00373235, 3 },
  { 0x00383235, 3 },
  { 0x00393235, 3 },
  { 0x00303335, 3 },
  { 0x00313335, 3 },
  { 0x00323335, 3 },
  { 0x00333335, 3 },
  { 0x00343335, 3 },
  { 0x00353335, 3 },
  { 0x00363335, 3 },
  { 0x00373335, 3 },
  { 0x00383335, 3 },
  { 0x00393335, 3 },
  { 0x00303435, 3 },
  { 0x00313435, 3 },
  { 0x00323435, 3 },
  { 0x00333435, 3 },
  { 0x00343435, 3 },
  { 0x00353435, 3 },
  { 0x00363435, 3 },
  { 0x00373435, 3 },
  { 0x00383435, 3 },
  { 0x00393435, 3 },
  { 0x00303535, 3 },
  { 0x00313535, 3 },
  { 0x00323535, 3 },
  { 0x00333535, 3 },
  { 0x00343535, 3 },
  { 0x00353535, 3 },
  { 0x00363535, 3 },
  { 0x00373535, 3 },
  { 0x00383535, 3 },
  { 0x00393535, 3 },
  { 0x00303635, 3 },
  { 0x00313635, 3 },
  { 0x00323635, 3 },
  { 0x00333635, 3 },
  { 0x00343635, 3 },
  { 0x00353635, 3 },
  { 0x00363635, 3 },
  { 0x00373635, 3 },
  { 0x00383635, 3 },
  { 0x00393635, 3 },
  { 0x00303735, 3 },
  { 0x00313735, 3 },
  { 0x00323735, 3 },
  { 0x00333735, 3 },
  { 0x00343735, 3 },
  { 0x00353735, 3 },
  { 0x00363735, 3 },
  { 0x00373735, 3 },
  { 0x00383735, 3 },
  { 0x00393735, 3 },
  { 0x00303835, 3 },
  { 0x00313835, 3 },
  { 0x00323835, 3 },
  { 0x00333835, 3 },
  { 0x00343835, 3 },
  { 0x00353835, 3 },
  { 0x00363835, 3 },
  { 0x00373835, 3 },
  { 0x00383835, 3 },
  { 0x00393835, 3 },
  { 0x00303935, 3 },
  { 0x00313935, 3 },
  { 0x00323935, 3 },
  { 0x00333935, 3 },
  { 0x00343935, 3 },
  { 0x00353935, 3 },
  { 0x00363935, 3 },
  { 0x00373935, 3 },
  { 0x00383935, 3 },
  { 0x00393935, 3 },
  { 0x00303036, 3 },
  { 0x00313036, 3 },
  { 0x00323036, 3 },
  { 0x00333036, 3 },
  { 0x00343036, 3 },
  { 0x00353036, 3 },
  { 0x00363036, 3 },
  { 0x00373036, 3 },
  { 0x00383036, 3 },
  { 0x00393036, 3 },
  { 0x00303136, 3 },
  { 0x00313136, 3 },
  { 0x00323136, 3 },
  { 0x00333136, 3 },
  { 0x00343136, 3 },
  { 0x00353136, 3 },
  { 0x00363136, 3 },
  { 0x00373136, 3 },
  { 0x00383136, 3 },
  { 0x00393136, 3 },
  { 0x00303236, 3 },
  { 0x00313236, 3 },
  { 0x00323236, 3 },
  { 0x00333236, 3 },
  { 0x00343236, 3 },
  { 0x00353236, 3 },
  { 0x00363236, 3 },
  { 0x00373236, 3 },
  { 0x00383236, 3 },
  { 0x00393236, 3 },
  { 0x00303336, 3 },
  { 0x00313336, 3 },
  { 0x00323336, 3 },
  { 0x00333336, 3 },
  { 0x00343336, 3 },
  { 0x00353336, 3 },
  { 0x00363336, 3 },
  { 0x00373336, 3 },
  { 0x00383336, 3 },
  { 0x00393336, 3 },
  { 0x00303436, 3 },
  { 0x00313436, 3 },
  { 0x00323436, 3 },
  { 0x00333436, 3 },
  { 0x00343436, 3 },
  { 0x00353436, 3 },
  { 0x00363436, 3 },
  { 0x00373436, 3 },
  { 0x00383436, 3 },
  { 0x00393436, 3 },
  { 0x00303536, 3 },
  { 0x00313536, 3 },
  { 0x00323536, 3 },
  { 0x00333536, 3 },
  { 0x00343536, 3 },
  { 0x00353536, 3 },
  { 0x00363536, 3 },
  { 0x00373536, 3 },
  { 0x00383536, 3 },
  { 0x00393536, 3 },
  { 0x00303636, 3 },
  { 0x00313636, 3 },
  { 0x00323636, 3 },
  { 0x00333636, 3 },
  { 0x00343636, 3 },
  { 0x00353636, 3 },
  { 0x00363636, 3 },
  { 0x00373636, 3 },
  { 0x00383636, 3 },
  { 0x00393636, 3 },
  { 0x00303736, 3 },
  { 0x00313736, 3 },
  { 0x00323736, 3 },
  { 0x00333736, 3 },
  { 0x00343736, 3 },
  { 0x00353736, 3 },
  { 0x00363736, 3 },
  { 0x00373736, 3 },
  { 0x00383736, 3 },
  { 0x00393736, 3 },
  { 0x00303836, 3 },
  { 0x00313836, 3 },
  { 0x00323836, 3 },
  { 0x00333836, 3 },
  { 0x00343836, 3 },
  { 0x00353836, 3 },
  { 0x00363836, 3 },
  { 0x00373836, 3 },
  { 0x00383836, 3 },
  { 0x00393836, 3 },
  { 0x00303936, 3 },
  { 0x00313936, 3 },
  { 0x00323936, 3 },
  { 0x00333936, 3 },
  { 0x00343936, 3 },
  { 0x00353936, 3 },
  { 0x00363936, 3 },
  { 0x00373936, 3 },
  { 0x00383936, 3 },
  { 0x00393936, 3 },
  { 0x00303037, 3 },
  { 0x00313037, 3 },
  { 0x00323037, 3 },
  { 0x00333037, 3 },
  { 0x00343037, 3 },
  { 0x00353037, 3 },
  { 0x00363037, 3 },
  { 0x00373037, 3 },
  { 0x00383037, 3 },
  { 0x00393037, 3 },
  { 0x00303137, 3 },
  { 0x00313137, 3 },
  { 0x00323137, 3 },
  { 0x00333137, 3 },
  { 0x00343137, 3 },
  { 0x00353137, 3 },
  { 0x00363137, 3 },
  { 0x00373137, 3 },
  { 0x00383137, 3 },
  { 0x00393137, 3 },
  { 0x00303237, 3 },
  { 0x00313237, 3 },
  { 0x00323237, 3 },
  { 0x00333237, 3 },
  { 0x00343237, 3 },
  { 0x00353237, 3 },
  { 0x00363237, 3 },
  { 0x00373237, 3 },
  { 0x00383237, 3 },
  { 0x00393237, 3 },
  { 0x00303337, 3 },
  { 0x00313337, 3 },
  { 0x00323337, 3 },
  { 0x00333337, 3 },
  { 0x00343337, 3 },
  { 0x00353337, 3 },
  { 0x00363337, 3 },
  { 0x00373337, 3 },
  { 0x00383337, 3 },
  { 0x00393337, 3 },
  { 0x00303437, 3 },
  { 0x00313437, 3 },
  { 0x00323437, 3 },
  { 0x00333437, 3 },
  { 0x00343437, 3 },
  { 0x00353437, 3 },
  { 0x00363437, 3 },
  { 0x00373437, 3 },
  { 0x00383437, 3 },
  { 0x00393437, 3 },
  { 0x00303537, 3 },
  { 0x00313537, 3 },
  { 0x00323537, 3 },
  { 0x00333537, 3 },
  { 0x00343537, 3 },
  { 0x00353537, 3 },
  { 0x00363537, 3 },
  { 0x00373537, 3 },
  { 0x00383537, 3 },
  { 0x00393537, 3 },
  { 0x00303637, 3 },
  { 0x00313637, 3 },
  { 0x00323637, 3 },
  { 0x00333637, 3 },
  { 0x00343637, 3 },
  { 0x00353637, 3 },
  { 0x00363637, 3 },
  { 0x00373637, 3 },
  { 0x00383637, 3 },
  { 0x00393637, 3 },
  { 0x00303737, 3 },
  { 0x00313737, 3 },
  { 0x00323737, 3 },
  { 0x00333737, 3 },
  { 0x00343737, 3 },
  { 0x00353737, 3 },
  { 0x00363737, 3 },
  { 0x00373737, 3 },
  { 0x00383737, 3 },
  { 0x00393737, 3 },
  { 0x00303837, 3 },
  { 0x00313837, 3 },
  { 0x00323837, 3 },
  { 0x00333837, 3 },
  { 0x00343837, 3 },
  { 0x00353837, 3 },
  { 0x00363837, 3 },
  { 0x00373837, 3 },
  { 0x00383837, 3 },
  { 0x00393837, 3 },
  { 0x00303937, 3 },
  { 0x00313937, 3 },
  { 0x00323937, 3 },
  { 0x00333937, 3 },
  { 0x00343937, 3 },
  { 0x00353937, 3 },
  { 0x00363937, 3 },
  { 0x00373937, 3 },
  { 0x00383937, 3 },
  { 0x00393937, 3 },
  { 0x00303038, 3 },
  { 0x00313038, 3 },
  { 0x00323038, 3 },
  { 0x00333038, 3 },
  { 0x00343038, 3 },
  { 0x00353038, 3 },
  { 0x00363038, 3 },
  { 0x00373038, 3 },
  { 0x00383038, 3 },
  { 0x00393038, 3 },
  { 0x00303138, 3 },
  { 0x00313138, 3 },
  { 0x00323138, 3 },
  { 0x00333138, 3 },
  { 0x00343138, 3 },
  { 0x00353138, 3 },
  { 0x00363138, 3 },
  { 0x00373138, 3 },
  { 0x00383138, 3 },
  { 0x00393138, 3 },
  { 0x00303238, 3 },
  { 0x00313238, 3 },
  { 0x00323238, 3 },
  { 0x00333238, 3 },
  { 0x00343238, 3 },
  { 0x00353238, 3 },
  { 0x00363238, 3 },
  { 0x00373238, 3 },
  { 0x00383238, 3 },
  { 0x00393238, 3 },
  { 0x00303338, 3 },
  { 0x00313338, 3 },
  { 0x00323338, 3 },
  { 0x00333338, 3 },
  { 0x00343338, 3 },
  { 0x00353338, 3 },
  { 0x00363338, 3 },
  { 0x00373338, 3 },
  { 0x00383338, 3 },
  { 0x00393338, 3 },
  { 0x00303438, 3 },
  { 0x00313438, 3 },
  { 0x00323438, 3 },
  { 0x00333438, 3 },
  { 0x00343438, 3 },
  { 0x00353438, 3 },
  { 0x00363438, 3 },
  { 0x00373438, 3 },
  { 0x00383438, 3 },
  { 0x00393438, 3 },
  { 0x00303538, 3 },
  { 0x00313538, 3 },
  { 0x00323538, 3 },
  { 0x00333538, 3 },
  { 0x00343538, 3 },
  { 0x00353538, 3 },
  { 0x00363538, 3 },
  { 0x00373538, 3 },
  { 0x00383538, 3 },
  { 0x00393538, 3 },
  { 0x00303638, 3 },
  { 0x00313638, 3 },
  { 0x00323638, 3 },
  { 0x00333638, 3 },
  { 0x00343638, 3 },
  { 0x00353638, 3 },
  { 0x00363638, 3 },
  { 0x00373638, 3 },
  { 0x00383638, 3 },
  { 0x00393638, 3 },
  { 0x00303738, 3 },
  { 0x00313738, 3 },
  { 0x00323738, 3 },
  { 0x00333738, 3 },
  { 0x00343738, 3 },
  { 0x00353738, 3 },
  { 0x00363738, 3 },
  { 0x00373738, 3 },
  { 0x00383738, 3 },
  { 0x00393738, 3 },
  { 0x00303838, 3 },
  { 0x00313838, 3 },
  { 0x00323838, 3 },
  { 0x00333838, 3 },
  { 0x00343838, 3 },
  { 0x00353838, 3 },
  { 0x00363838, 3 },
  { 0x00373838, 3 },
  { 0x00383838, 3 },
  { 0x00393838, 3 },
  { 0x00303938, 3 },
  { 0x00313938, 3 },
  { 0x00323938, 3 },
  { 0x00333938, 3 },
  { 0x00343938, 3 },
  { 0x00353938, 3 },
  { 0x00363938, 3 },
  { 0x00373938, 3 },
  { 0x00383938, 3 },
  { 0x00393938, 3 },
  { 0x00303039, 3 },
  { 0x00313039, 3 },
  { 0x00323039, 3 },
  { 0x00333039, 3 },
  { 0x00343039, 3 },
  { 0x00353039, 3 },
  { 0x00363039, 3 },
  { 0x00373039, 3 },
  { 0x00383039, 3 },
  { 0x00393039, 3 },
  { 0x00303139, 3 },
  { 0x00313139, 3 },
  { 0x00323139, 3 },
  { 0x00333139, 3 },
  { 0x00343139, 3 },
  { 0x00353139, 3 },
  { 0x00363139, 3 },
  { 0x00373139, 3 },
  { 0x00383139, 3 },
  { 0x00393139, 3 },
  { 0x00303239, 3 },
  { 0x00313239, 3 },
  { 0x00323239, 3 },
  { 0x00333239, 3 },
  { 0x00343239, 3 },
  { 0x00353239, 3 },
  { 0x00363239, 3 },
  { 0x00373239, 3 },
  { 0x00383239, 3 },
  { 0x00393239, 3 },
  { 0x00303339, 3 },
  { 0x00313339, 3 },
  { 0x00323339, 3 },
  { 0x00333339, 3 },
  { 0x00343339, 3 },
  { 0x00353339, 3 },
  { 0x00363339, 3 },
  { 0x00373339, 3 },
  { 0x00383339, 3 },
  { 0x00393339, 3 },
  { 0x00303439, 3 },
  { 0x00313439, 3 },
  { 0x00323439, 3 },
  { 0x00333439, 3 },
  { 0x00343439, 3 },
  { 0x00353439, 3 },
  { 0x00363439, 3 },
  { 0x00373439, 3 },
  { 0x00383439, 3 },
  { 0x00393439, 3 },
  { 0x00303539, 3 },
  { 0x00313539, 3 },
  { 0x00323539, 3 },
  { 0x00333539, 3 },
  { 0x00343539, 3 },
  { 0x00353539, 3 },
  { 0x00363539, 3 },
  { 0x00373539, 3 },
  { 0x00383539, 3 },
  { 0x00393539, 3 },
  { 0x00303639, 3 },
  { 0x00313639, 3 },
  { 0x00323639, 3 },
  { 0x00333639, 3 },
  { 0x00343639, 3 },
  { 0x00353639, 3 },
  { 0x00363639, 3 },
  { 0x00373639, 3 },
  { 0x00383639, 3 },
  { 0x00393639, 3 },
  { 0x00303739, 3 },
  { 0x00313739, 3 },
  { 0x00323739, 3 },
  { 0x00333739, 3 },
  { 0x00343739, 3 },
  { 0x00353739, 3 },
  { 0x00363739, 3 },
  { 0x00373739, 3 },
  { 0x00383739, 3 },
  { 0x00393739, 3 },
  { 0x00303839, 3 },
  { 0x00313839, 3 },
  { 0x00323839, 3 },
  { 0x00333839, 3 },
  { 0x00343839, 3 },
  { 0x00353839, 3 },
  { 0x00363839, 3 },
  { 0x00373839, 3 },
  { 0x00383839, 3 },
  { 0x00393839, 3 },
  { 0x00303939, 3 },
  { 0x00313939, 3 },
  { 0x00323939, 3 },
  { 0x00333939, 3 },
  { 0x00343939, 3 },
  { 0x00353939, 3 },
  { 0x00363939, 3 },
  { 0x00373939, 3 },
  { 0x00383939, 3 },
  { 0x00393939, 3 },
  { 0x30303031, 4 },
  { 0x31303031, 4 },
  { 0x32303031, 4 },
  { 0x33303031, 4 },
  { 0x34303031, 4 },
  { 0x35303031, 4 },
  { 0x36303031, 4 },
  { 0x37303031, 4 },
  { 0x38303031, 4 },
  { 0x39303031, 4 },
  { 0x30313031, 4 },
  { 0x31313031, 4 },
  { 0x32313031, 4 },
  { 0x33313031, 4 },
  { 0x34313031, 4 },
  { 0x35313031, 4 },
  { 0x36313031, 4 },
  { 0x37313031, 4 },
  { 0x38313031, 4 },
  { 0x39313031, 4 },
  { 0x30323031, 4 },
  { 0x31323031, 4 },
  { 0x32323031, 4 },
  { 0x33323031, 4 }
};

void append_word (u32 w0[4], u32 w1[4], const u32 append[4], const u32 offset)
{
  switch (offset)
  {
    case 1:
      w0[0] = w0[0]           | append[0] <<  8;
      w0[1] = append[0] >> 24 | append[1] <<  8;
      w0[2] = append[1] >> 24 | append[2] <<  8;
      w0[3] = append[2] >> 24 | append[3] <<  8;
      break;

    case 2:
      w0[0] = w0[0]           | append[0] << 16;
      w0[1] = append[0] >> 16 | append[1] << 16;
      w0[2] = append[1] >> 16 | append[2] << 16;
      w0[3] = append[2] >> 16 | append[3] << 16;
      break;

    case 3:
      w0[0] = w0[0]           | append[0] << 24;
      w0[1] = append[0] >>  8 | append[1] << 24;
      w0[2] = append[1] >>  8 | append[2] << 24;
      w0[3] = append[2] >>  8 | append[3] << 24;
      break;

    case 4:
      w0[1] = append[0];
      w0[2] = append[1];
      w0[3] = append[2];
      w1[0] = append[3];
      break;
  }
}

void append_salt (u32 w0[4], u32 w1[4], u32 w2[4], const u32 append[5], const u32 offset)
{
  u32 tmp0;
  u32 tmp1;
  u32 tmp2;
  u32 tmp3;
  u32 tmp4;
  u32 tmp5;

  #if defined IS_AMD || defined IS_GENERIC

  const int offset_minus_4 = 4 - (offset & 3);

  tmp0 = amd_bytealign (append[0],         0, offset_minus_4);
  tmp1 = amd_bytealign (append[1], append[0], offset_minus_4);
  tmp2 = amd_bytealign (append[2], append[1], offset_minus_4);
  tmp3 = amd_bytealign (append[3], append[2], offset_minus_4);
  tmp4 = amd_bytealign (append[4], append[3], offset_minus_4);
  tmp5 = amd_bytealign (        0, append[4], offset_minus_4);

  const u32 mod = offset & 3;

  if (mod == 0)
  {
    tmp0 = tmp1;
    tmp1 = tmp2;
    tmp2 = tmp3;
    tmp3 = tmp4;
    tmp4 = tmp5;
    tmp5 = 0;
  }

  #endif

  #ifdef IS_NV

  const int offset_minus_4 = 4 - (offset & 3);

  const int selector = (0x76543210 >> (offset_minus_4 * 4)) & 0xffff;

  tmp0 = __byte_perm (        0, append[0], selector);
  tmp1 = __byte_perm (append[0], append[1], selector);
  tmp2 = __byte_perm (append[1], append[2], selector);
  tmp3 = __byte_perm (append[2], append[3], selector);
  tmp4 = __byte_perm (append[3], append[4], selector);
  tmp5 = __byte_perm (append[4],         0, selector);

  #endif

  const u32 div = offset / 4;

  switch (div)
  {
    case  0:  w0[0] |= tmp0;
              w0[1]  = tmp1;
              w0[2]  = tmp2;
              w0[3]  = tmp3;
              w1[0]  = tmp4;
              w1[1]  = tmp5;
              break;
    case  1:  w0[1] |= tmp0;
              w0[2]  = tmp1;
              w0[3]  = tmp2;
              w1[0]  = tmp3;
              w1[1]  = tmp4;
              w1[2]  = tmp5;
              break;
    case  2:  w0[2] |= tmp0;
              w0[3]  = tmp1;
              w1[0]  = tmp2;
              w1[1]  = tmp3;
              w1[2]  = tmp4;
              w1[3]  = tmp5;
              break;
    case  3:  w0[3] |= tmp0;
              w1[0]  = tmp1;
              w1[1]  = tmp2;
              w1[2]  = tmp3;
              w1[3]  = tmp4;
              w2[0]  = tmp5;
              break;
    case  4:  w1[0] |= tmp0;
              w1[1]  = tmp1;
              w1[2]  = tmp2;
              w1[3]  = tmp3;
              w2[0]  = tmp4;
              w2[1]  = tmp5;
              break;
  }
}

void sha1_transform (const u32 w0[4], const u32 w1[4], const u32 w2[4], const u32 w3[4], u32 digest[5])
{
  u32 A = digest[0];
  u32 B = digest[1];
  u32 C = digest[2];
  u32 D = digest[3];
  u32 E = digest[4];

  u32 w0_t = w0[0];
  u32 w1_t = w0[1];
  u32 w2_t = w0[2];
  u32 w3_t = w0[3];
  u32 w4_t = w1[0];
  u32 w5_t = w1[1];
  u32 w6_t = w1[2];
  u32 w7_t = w1[3];
  u32 w8_t = w2[0];
  u32 w9_t = w2[1];
  u32 wa_t = w2[2];
  u32 wb_t = w2[3];
  u32 wc_t = w3[0];
  u32 wd_t = w3[1];
  u32 we_t = w3[2];
  u32 wf_t = w3[3];

  #undef K
  #define K SHA1C00

  SHA1_STEP (SHA1_F0o, A, B, C, D, E, w0_t);
  SHA1_STEP (SHA1_F0o, E, A, B, C, D, w1_t);
  SHA1_STEP (SHA1_F0o, D, E, A, B, C, w2_t);
  SHA1_STEP (SHA1_F0o, C, D, E, A, B, w3_t);
  SHA1_STEP (SHA1_F0o, B, C, D, E, A, w4_t);
  SHA1_STEP (SHA1_F0o, A, B, C, D, E, w5_t);
  SHA1_STEP (SHA1_F0o, E, A, B, C, D, w6_t);
  SHA1_STEP (SHA1_F0o, D, E, A, B, C, w7_t);
  SHA1_STEP (SHA1_F0o, C, D, E, A, B, w8_t);
  SHA1_STEP (SHA1_F0o, B, C, D, E, A, w9_t);
  SHA1_STEP (SHA1_F0o, A, B, C, D, E, wa_t);
  SHA1_STEP (SHA1_F0o, E, A, B, C, D, wb_t);
  SHA1_STEP (SHA1_F0o, D, E, A, B, C, wc_t);
  SHA1_STEP (SHA1_F0o, C, D, E, A, B, wd_t);
  SHA1_STEP (SHA1_F0o, B, C, D, E, A, we_t);
  SHA1_STEP (SHA1_F0o, A, B, C, D, E, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F0o, E, A, B, C, D, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F0o, D, E, A, B, C, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F0o, C, D, E, A, B, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F0o, B, C, D, E, A, w3_t);

  #undef K
  #define K SHA1C01

  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w7_t);

  #undef K
  #define K SHA1C02

  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, wb_t);

  #undef K
  #define K SHA1C03

  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, wf_t);

  digest[0] += A;
  digest[1] += B;
  digest[2] += C;
  digest[3] += D;
  digest[4] += E;
}

__kernel void m05800_init (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global androidpin_tmp_t *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 word_buf[4];

  word_buf[0] = pws[gid].i[ 0];
  word_buf[1] = pws[gid].i[ 1];
  word_buf[2] = pws[gid].i[ 2];
  word_buf[3] = pws[gid].i[ 3];

  const u32 pw_len = pws[gid].pw_len;

  /**
   * salt
   */

  u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 salt_buf[5];

  salt_buf[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf[3] = salt_bufs[salt_pos].salt_buf[3];
  salt_buf[4] = salt_bufs[salt_pos].salt_buf[4];

  /**
   * init
   */

  const u32 pc_len = 1;
  const u32 pc_dec = 0x30;

  u32 data0[4] = { 0, 0, 0, 0 };
  u32 data1[4] = { 0, 0, 0, 0 };
  u32 data2[4] = { 0, 0, 0, 0 };

  data0[0] = pc_dec;

  append_word (data0, data1, word_buf, pc_len);

  append_salt (data0, data1, data2, salt_buf, pc_len + pw_len);

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = swap32 (data0[0]);
  w0[1] = swap32 (data0[1]);
  w0[2] = swap32 (data0[2]);
  w0[3] = swap32 (data0[3]);
  w1[0] = swap32 (data1[0]);
  w1[1] = swap32 (data1[1]);
  w1[2] = swap32 (data1[2]);
  w1[3] = swap32 (data1[3]);
  w2[0] = swap32 (data2[0]);
  w2[1] = swap32 (data2[1]);
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (pc_len + pw_len + salt_len) * 8;

  u32 digest[5];

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  sha1_transform (w0, w1, w2, w3, digest);

  tmps[gid].digest_buf[0] = digest[0];
  tmps[gid].digest_buf[1] = digest[1];
  tmps[gid].digest_buf[2] = digest[2];
  tmps[gid].digest_buf[3] = digest[3];
  tmps[gid].digest_buf[4] = digest[4];
}

__kernel void m05800_loop (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global androidpin_tmp_t *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

  /**
   * cache precomputed conversion table in shared memory
   */

  __local entry_t s_pc[1024];

  for (u32 i = lid; i < 1024; i += lsz)
  {
    s_pc[i] = pc[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 word_buf[4];

  word_buf[0] = pws[gid].i[ 0];
  word_buf[1] = pws[gid].i[ 1];
  word_buf[2] = pws[gid].i[ 2];
  word_buf[3] = pws[gid].i[ 3];

  const u32 pw_len = pws[gid].pw_len;

  u32 digest[5];

  digest[0] = tmps[gid].digest_buf[0];
  digest[1] = tmps[gid].digest_buf[1];
  digest[2] = tmps[gid].digest_buf[2];
  digest[3] = tmps[gid].digest_buf[3];
  digest[4] = tmps[gid].digest_buf[4];

  /**
   * salt
   */

  u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 salt_buf[5];

  salt_buf[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf[3] = salt_bufs[salt_pos].salt_buf[3];
  salt_buf[4] = salt_bufs[salt_pos].salt_buf[4];

  /**
   * loop
   */

  for (u32 i = 0, j = loop_pos + 1; i < loop_cnt; i++, j++)
  {
    const u32 pc_len = s_pc[j].len;
    const u32 pc_dec = s_pc[j].dec;

    u32 data0[4] = { 0, 0, 0, 0 };
    u32 data1[4] = { 0, 0, 0, 0 };
    u32 data2[4] = { 0, 0, 0, 0 };

    data0[0] = pc_dec;

    append_word (data0, data1, word_buf, pc_len);

    append_salt (data0, data1, data2, salt_buf, pc_len + pw_len);

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = swap32 (data0[0]);
    w1[2] = swap32 (data0[1]);
    w1[3] = swap32 (data0[2]);
    w2[0] = swap32 (data0[3]);
    w2[1] = swap32 (data1[0]);
    w2[2] = swap32 (data1[1]);
    w2[3] = swap32 (data1[2]);
    w3[0] = swap32 (data1[3]);
    w3[1] = swap32 (data2[0]);
    w3[2] = 0;
    w3[3] = (20 + pc_len + pw_len + salt_len) * 8;

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0, w1, w2, w3, digest);
  }

  tmps[gid].digest_buf[0] = digest[0];
  tmps[gid].digest_buf[1] = digest[1];
  tmps[gid].digest_buf[2] = digest[2];
  tmps[gid].digest_buf[3] = digest[3];
  tmps[gid].digest_buf[4] = digest[4];
}

__kernel void m05800_comp (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global androidpin_tmp_t *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u32 lid = get_local_id (0);

  /**
   * digest
   */

  const u32 r0 = tmps[gid].digest_buf[DGST_R0];
  const u32 r1 = tmps[gid].digest_buf[DGST_R1];
  const u32 r2 = tmps[gid].digest_buf[DGST_R2];
  const u32 r3 = tmps[gid].digest_buf[DGST_R3];

  #define il_pos 0

  #include COMPARE_M
}
