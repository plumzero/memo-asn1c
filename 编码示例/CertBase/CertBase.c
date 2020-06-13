#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include "CertificateBase.h"

#include <time.h>
#include <stddef.h>

#define SEQUENCE_OF_SIZE        4                           // 测试中，不要太大
#define Y_SIZE                  2
#define Z_SIZE                  5

#define VERSION                 3

#define STOP_IT_IF_ERROR(assertion, variable, format, ...)      \
    do {                                                        \
        if (assertion) {                                        \
            fprintf(stderr, "%d %s ", __LINE__, #variable);     \
            fprintf(stderr, format, ##__VA_ARGS__);             \
            goto cleanup;                                       \
        }                                                       \
    } while (0)

#define LOG_ERR(variable, format, ...)                          \
    do {                                                        \
        fprintf(stderr, "%d %s ", __LINE__, #variable);         \
        fprintf(stderr, format, ##__VA_ARGS__);                 \
    } while(0)

#define FILL_WITH_OCTET_STRING(Ivalue, Ibuf, Isize, oRet)       \
    do {                                                        \
        OCTET_STRING_t ostr;                                    \
        memset(&ostr, 0, sizeof(OCTET_STRING_t));               \
        oRet = OCTET_STRING_fromBuf(&ostr, Ibuf, Isize);        \
        Ivalue = ostr;                                          \
    } while (0)

static const unsigned int ui8u = 250;               // 小于 2^8
static const unsigned int ui16u = 65500;            // 小于 2^16
static const unsigned int uinone = 0;               // NULL_t 专用
static const signed  long l9u_mis = -666666666;     // [ -9e8, 9e8 ]    
static const signed  long l9u_pls = 8888888888;     // [ -9e8, 9e8 ]
static const signed  long l18u_mis = -1600000000;   // ( -18e8, 18e8 ]
static const signed  long l18u_pls = 1700000000;    // ( -18e8, 18e8 ]
static const unsigned long ul = 1234567890;

static const unsigned char uppercase[] = {
                            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
                            'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
                        };
static const unsigned char lowercase[] = {
                            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                            'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
                        };
static const unsigned char digits[] = {
                            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
                        };
static const unsigned char reuppercase[] = {
                            'Z', 'Y', 'X', 'W', 'V', 'U', 'T', 'S', 'R', 'Q', 'P', 'O',
                            'N', 'M', 'L', 'K', 'J', 'I', 'H', 'G', 'F', 'E', 'D', 'C', 'B', 'A'
                        };
static const unsigned char relowercase[] = {
                            'z', 'y', 'x', 'w', 'v', 'u', 't', 's', 'r', 'q', 'p', 'o',
                            'n', 'm', 'l', 'k', 'j', 'i', 'h', 'g', 'f', 'e', 'd', 'c', 'b', 'a'
                        };
static const unsigned char redigits[] = {               
                            '9', '8', '7', '6', '5', '4', '3', '2', '1', '0'
                        };
static const unsigned char ucsu256u[] = {       // 小于 255， 大于 64
                        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
                        'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                        'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                        'Z', 'Y', 'X', 'W', 'V', 'U', 'T', 'S', 'R', 'Q', 'P', 'O',
                        'N', 'M', 'L', 'K', 'J', 'I', 'H', 'G', 'F', 'E', 'D', 'C', 'B', 'A',
                        'z', 'y', 'x', 'w', 'v', 'u', 't', 's', 'r', 'q', 'p', 'o',
                        'n', 'm', 'l', 'k', 'j', 'i', 'h', 'g', 'f', 'e', 'd', 'c', 'b', 'a',
                        '9', '8', '7', '6', '5', '4', '3', '2', '1', '0'
                        };
static const unsigned char ucsu64u[] = {            // 小于 64，但也要足够多
                        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
                        'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                        'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',                       
                        };

static int write_callback(const void *buffer, size_t size, void *app_key)
{
    FILE *fp = app_key;
    size_t wrote = fwrite(buffer, 1, size, fp);
    return (wrote == size) ? 0 : -1;
}

/** 
    说明：
        对 103097 证书进行 coer 全编码。
        asn1 文件为自己修改后的可处理文件，只作参考学习，不用于具体生产中。
        
    编码验证：
        openssl asn1parse -inform der -in out.der -i    // 本测试为 coer 编码，不适用
        可以将 oer_encode 改为 der_encode 以产生 der 编码
        
    待解决问题:
        1. 流无法输出到文件 -> 解决完毕。整个编码完成之后才能输出到文件，否则会跳过写回调。
        2. 内存泄漏检测 -> 未进行
           valgrind --tool=memcheck --leak-check=full ./st2coer out.coer
    关于 asn1c 库的小心小心：
        1. 虽然说 UTF8String_t 是 OCTET_STRING_t 的别名，
            typedef OCTET_STRING_t UTF8String_t;
           但对 UTF8String_t 使用 OCTET_STRING_fromBuf 报段错误。
           应该把 UTF8String_t 当作一种不同于 OCTET_STRING_t 的字符串来处理。
        2. 关于写入磁盘文件。只有当整个 asn1 文件编码完成之后，才能写入文件。
        3. 指针分配堆内存，非指针分配栈内存，是严格遵守，否则在释放时容易报段错误。
        4. 对于 SEQUENCE_OF ，不能像下面这样一次性分配内存：
            calloc(1, sizeof(struct SinglePart) * SEQUENCE_OF_SIZE);
           而应该这样一点点分配内存：
            calloc(1, sizeof(struct SinglePart));
            calloc(1, sizeof(struct SinglePart));
            ...
            calloc(1, sizeof(struct SinglePart));
           一共分配 SEQUENCE_OF_SIZE 次。
           否则会报段错误。
        5. 所有的指针都初始化为 NULL 。
        6. 不重复使用所定义的变量。
    
    注意：
        1. 本编码为全证书编码，生成的 coer 文件在 https://asn1.io/asn1playground/ 中检测报错，
           但这并不说明本编码是错误的，极有可能是 asn1 文件中的依赖关系没有处理好；
 */

int main(int argc, char *argv[]) 
{
    int RET = -1, _ret;
    asn_enc_rval_t ec;
    FILE *fp = NULL;
    int i, ii, iii; 

    // 指针不可复用
    CertificateBase_t                       *pst_certificate_base = NULL;
    struct GroupLinkageValue                *pst_group_linkage_value = NULL;
    struct GeographicRegion                 *pst_region = NULL;
    SubjectAssurance_t                      *pbs1_assurance_level = NULL;
    struct SequenceOfPsidSsp                *pst_app_permissions = NULL;
    struct SequenceOfPsidGroupPermissions   *pst_cert_issue_permissions = NULL;         
    struct SequenceOfPsidGroupPermissions   *pst_cert_request_permissions = NULL;
    NULL_t                                  *pi_can_request_rollover = NULL;
    struct PublicEncryptionKey              *pst_public_encryption_key = NULL;
    struct Signature                        *pst_signature = NULL;

    struct RectangularRegion* ps_rect_region[SEQUENCE_OF_SIZE] = { NULL };
    struct TwoDLocation* ps_two_location[SEQUENCE_OF_SIZE] = { NULL };
    struct IdentifiedRegion* ps_iden_region[SEQUENCE_OF_SIZE] = { NULL };
    struct CountryAndSubregions* pss_country_subregions[SEQUENCE_OF_SIZE][Y_SIZE] = { NULL };
    struct RegionAndSubregions* pss_region_subregions[SEQUENCE_OF_SIZE][Y_SIZE] = { NULL };
    Uint16_t* psss_uint16[SEQUENCE_OF_SIZE][Y_SIZE][Z_SIZE] = { NULL };
    Uint8_t *pss_uint8[SEQUENCE_OF_SIZE][Y_SIZE] = { NULL };
    struct PsidSsp* ps_psid_ssp[SEQUENCE_OF_SIZE] = { NULL };
    struct PsidGroupPermissions* ps_psid_group_permissions[SEQUENCE_OF_SIZE] = { NULL };
    struct PsidSspRange* pss_psid_ssp_range[SEQUENCE_OF_SIZE][Y_SIZE] = { NULL };
    struct OCTET_STRING* psss_octet_string[SEQUENCE_OF_SIZE][Y_SIZE][Z_SIZE] = { NULL };
    struct PsidGroupPermissions* ps_psid_group_permissions_t[SEQUENCE_OF_SIZE] = { NULL };
    struct PsidSspRange* pss_psid_ssp_range_t[SEQUENCE_OF_SIZE][Y_SIZE] = { NULL };
    struct OCTET_STRING* psss_octet_string_t[SEQUENCE_OF_SIZE][Y_SIZE][Z_SIZE] = { NULL };
    
    // 参数校验
    if (argv[1] && (fp = fopen(argv[1], "wb")) == NULL) {
        fprintf(stderr, "%d ecode(%d): %s\n", __LINE__, errno, strerror(errno));
        goto cleanup;   
    }
    // 开始整理 ...
    pst_certificate_base = calloc(1, sizeof(CertificateBase_t));
    STOP_IT_IF_ERROR(NULL == pst_certificate_base, CertificateBase_t, "calloc failed\n");
    // 第 1 部分
    pst_certificate_base->version = VERSION;
    // 第 2 部分
    pst_certificate_base->type = CertificateType_explicit;  // CertificateType_implicit  CertificateType_explicit
    // 第 3 部分
    pst_certificate_base->issuer.present = IssuerIdentifier_PR_sha256AndDigest;
    switch(pst_certificate_base->issuer.present) {
    case IssuerIdentifier_PR_sha256AndDigest:
        FILL_WITH_OCTET_STRING(pst_certificate_base->issuer.choice.sha256AndDigest, uppercase, 8, _ret);
        STOP_IT_IF_ERROR(0 != _ret, HashedId8_t, "OCTET_STRING_fromBuf failed\n");
        break;
    case IssuerIdentifier_PR_self:
        pst_certificate_base->issuer.choice.self = HashAlgorithm_sha256;
        break;
    case IssuerIdentifier_PR_sha384AndDigest:
        FILL_WITH_OCTET_STRING(pst_certificate_base->issuer.choice.sha384AndDigest, lowercase, 8, _ret);
        STOP_IT_IF_ERROR(0 != _ret, HashedId8_t, "OCTET_STRING_fromBuf failed\n");
        break;
    default:
        LOG_ERR(IssuerIdentifier_PR, "no matched value\n");
        goto cleanup;
    }
    // 第 4 部分 又分 12 个小块
    // 第 4 部分第 1 小块  == CertificateId_t id 部分 ==
    pst_certificate_base->toBeSigned.id.present = CertificateId_PR_linkageData;
    switch (pst_certificate_base->toBeSigned.id.present) {
    case CertificateId_PR_linkageData:
        pst_certificate_base->toBeSigned.id.choice.linkageData.iCert = ui16u;
        
        FILL_WITH_OCTET_STRING(pst_certificate_base->toBeSigned.id.choice.linkageData.linkage_value, redigits, 9, _ret);
        STOP_IT_IF_ERROR(0 != _ret, LinkageValue_t, "OCTET_STRING_fromBuf failed\n");
        
        pst_group_linkage_value = calloc(1, sizeof(struct GroupLinkageValue));
        STOP_IT_IF_ERROR(NULL == pst_group_linkage_value, GroupLinkageValue_t, "calloc failed\n");
        FILL_WITH_OCTET_STRING(pst_group_linkage_value->jValue, reuppercase, 4, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        FILL_WITH_OCTET_STRING(pst_group_linkage_value->value, relowercase, 9, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        pst_certificate_base->toBeSigned.id.choice.linkageData.group_linkage_value = pst_group_linkage_value;
        break;
    case CertificateId_PR_name:
        FILL_WITH_OCTET_STRING(pst_certificate_base->toBeSigned.id.choice.name, ucsu256u, -1, _ret);
        STOP_IT_IF_ERROR(0 != _ret, Hostname_t, "OCTET_STRING_fromBuf failed\n");
        break;
    case CertificateId_PR_binaryId:
        FILL_WITH_OCTET_STRING(pst_certificate_base->toBeSigned.id.choice.binaryId, ucsu64u, -1, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        break;
    case CertificateId_PR_none:
        pst_certificate_base->toBeSigned.id.choice.none = uinone;
        break;
    default:
        LOG_ERR(CertificateId_PR, "no matched value\n");
        goto cleanup;
    }   
    // 第 4 部分第 2 小块 == HashedId3_t cracaId 部分 ==
    FILL_WITH_OCTET_STRING(pst_certificate_base->toBeSigned.cracaId, uppercase, 3, _ret);
    STOP_IT_IF_ERROR(0 != _ret, HashedId3_t, "OCTET_STRING_fromBuf failed\n");
    // 第 4 部分第 3 小块 == CrlSeries_t crlSeries 部分 ==
    pst_certificate_base->toBeSigned.crlSeries = ui16u;
    // 第 4 部分第 4 小块 == ValidityPeriod_t validityPeriod 部分 ==
    pst_certificate_base->toBeSigned.validityPeriod.start = time(NULL);
    pst_certificate_base->toBeSigned.validityPeriod.duration.present = Duration_PR_sixtyHours;
    switch (pst_certificate_base->toBeSigned.validityPeriod.duration.present) {
    case Duration_PR_microseconds:
        pst_certificate_base->toBeSigned.validityPeriod.duration.choice.microseconds = ui16u + Duration_PR_microseconds;
        break;
    case Duration_PR_milliseconds:
        pst_certificate_base->toBeSigned.validityPeriod.duration.choice.milliseconds = ui16u + Duration_PR_milliseconds;
        break;
    case Duration_PR_seconds:
        pst_certificate_base->toBeSigned.validityPeriod.duration.choice.seconds = ui16u + Duration_PR_seconds;
        break;
    case Duration_PR_minutes:
        pst_certificate_base->toBeSigned.validityPeriod.duration.choice.minutes = ui16u + Duration_PR_minutes;
        break;
    case Duration_PR_hours:
        pst_certificate_base->toBeSigned.validityPeriod.duration.choice.hours = ui16u + Duration_PR_hours;
        break;
    case Duration_PR_sixtyHours:
        pst_certificate_base->toBeSigned.validityPeriod.duration.choice.sixtyHours = ui16u + Duration_PR_sixtyHours;
        break;
    case Duration_PR_years:
        pst_certificate_base->toBeSigned.validityPeriod.duration.choice.years = ui16u + Duration_PR_years;
        break;
    default:
        LOG_ERR(Duration_PR, "no matched value\n");
        goto cleanup;
    }
    // 第 4 部分第 5 小块 == struct GeographicRegion *region 部分 ==
    pst_region = calloc(1, sizeof(struct GeographicRegion));
    STOP_IT_IF_ERROR(NULL == pst_region, GeographicRegion_t, "calloc failed\n");
    pst_region->present = GeographicRegion_PR_identifiedRegion;
    switch(pst_region->present) {
    case GeographicRegion_PR_circularRegion:
        pst_region->choice.circularRegion.center.latitude = l9u_mis;
        pst_region->choice.circularRegion.center.longitude = l18u_pls;
        pst_region->choice.circularRegion.radius = ui16u;
        break;
    case GeographicRegion_PR_rectangularRegion:
        for (i = 0; i < SEQUENCE_OF_SIZE; i++) {
            if (NULL == ps_rect_region[i]) {
                ps_rect_region[i] = (struct RectangularRegion*)calloc(1, sizeof(struct RectangularRegion));
                STOP_IT_IF_ERROR(NULL == ps_rect_region[i], RectangularRegion_t, "calloc failed\n");    
            }
            ps_rect_region[i]->northWest.latitude = l9u_mis + i * GeographicRegion_PR_rectangularRegion;
            ps_rect_region[i]->northWest.longitude = l18u_pls - i * GeographicRegion_PR_rectangularRegion;
            ps_rect_region[i]->southEast.latitude = l9u_pls - i * GeographicRegion_PR_rectangularRegion;
            ps_rect_region[i]->southEast.longitude = l18u_mis + i * GeographicRegion_PR_rectangularRegion;          
            _ret = asn_set_add(&pst_region->choice.rectangularRegion.list, ps_rect_region[i]);
            STOP_IT_IF_ERROR(0 != _ret, RectangularRegion_t, "asn_set_add failed\n");
        }
        break;
    case GeographicRegion_PR_polygonalRegion:
        for (i = 0; i < SEQUENCE_OF_SIZE; i++) {
            if (NULL == ps_two_location[i]) {
                ps_two_location[i] = (struct TwoDLocation*)calloc(1, sizeof(struct TwoDLocation));
                STOP_IT_IF_ERROR(NULL == ps_two_location[i], TwoDLocation_t, "calloc failed\n");
            }
            ps_two_location[i]->latitude = l9u_mis + i * GeographicRegion_PR_polygonalRegion;
            ps_two_location[i]->longitude = l18u_pls - i * GeographicRegion_PR_polygonalRegion;
            _ret = asn_set_add(&pst_region->choice.polygonalRegion.list, ps_two_location[i]);
            STOP_IT_IF_ERROR(0 != _ret, TwoDLocation_t, "asn_set_add failed\n");    
        }
        break;
    case GeographicRegion_PR_identifiedRegion:
        for (i = 0; i < SEQUENCE_OF_SIZE; i++) {
            if (NULL == ps_iden_region[i]) {
                ps_iden_region[i] = (struct IdentifiedRegion*)calloc(1, sizeof(struct IdentifiedRegion));
                STOP_IT_IF_ERROR(NULL == ps_iden_region[i], IdentifiedRegion_t, "calloc failed\n");
            }
            ps_iden_region[i]->present = (IdentifiedRegion_PR_countryOnly + i) % 3 + IdentifiedRegion_PR_countryOnly;
            switch (ps_iden_region[i]->present) {
            case IdentifiedRegion_PR_countryOnly:
                ps_iden_region[i]->choice.countryOnly = ui16u;
                break;
            case IdentifiedRegion_PR_countryAndRegions:
                ps_iden_region[i]->choice.countryAndRegions.countryOnly = ui16u;
                for (ii = 0; ii < Y_SIZE; ii++) {
                    if (NULL == pss_uint8[i][ii]) {
                        pss_uint8[i][ii] = calloc(1, sizeof(Uint8_t));
                        STOP_IT_IF_ERROR(NULL == pss_uint8[i][ii], Uint8_t, "calloc failed\n");
                    }
                    *pss_uint8[i][ii] = lowercase[i + ii];
                    _ret = asn_set_add(&ps_iden_region[i]->choice.countryAndRegions.regions.list, pss_uint8[i][ii]);
                    STOP_IT_IF_ERROR(0 != _ret, Uint8_t, "asn_set_add failed\n");
                }
                break;
            case IdentifiedRegion_PR_countryAndSubregions:
                ps_iden_region[i]->choice.countryAndSubregions.country = ui16u;
                for (ii = 0; ii < Y_SIZE; ii++) {
                    if (NULL == pss_region_subregions[i][ii]) {
                        pss_region_subregions[i][ii] = calloc(1, sizeof(struct RegionAndSubregions));
                        STOP_IT_IF_ERROR(NULL == pss_region_subregions[i][ii], RegionAndSubregions_t, 
                                                                                                "calloc failed\n");
                    }
                    pss_region_subregions[i][ii]->region = ui8u;
                    for (iii = 0; iii < Z_SIZE; iii++) {
                        if (NULL == psss_uint16[i][ii][iii]) {
                            psss_uint16[i][ii][iii] = calloc(1, sizeof(Uint16_t));
                            STOP_IT_IF_ERROR(NULL == psss_uint16[i][ii][iii], Uint16_t, "calloc failed\n");
                        }
                        *psss_uint16[i][ii][iii] = ucsu256u[i + ii + iii];
                        _ret = asn_set_add(&pss_region_subregions[i][ii]->subregions.list, psss_uint16[i][ii][iii]);
                        STOP_IT_IF_ERROR(0 != _ret, Uint16_t, "asn_set_add failed\n");
                    }
                    _ret = asn_set_add(&ps_iden_region[i]->choice.countryAndSubregions.regionAndSubregions.list, 
                                                                                    pss_region_subregions[i][ii]);
                    STOP_IT_IF_ERROR(0 != _ret, RegionAndSubregions_t, "asn_set_add failed\n");
                }
                break;
            default:
                LOG_ERR(IdentifiedRegion_PR, "no matched value\n");
                goto cleanup;       
            }
            _ret =  asn_set_add(&pst_region->choice.identifiedRegion.list, ps_iden_region[i]);
            STOP_IT_IF_ERROR(0 != _ret, IdentifiedRegion, "asn_set_add failed\n");
        }
        break;
    default:
        LOG_ERR(GeographicRegion_PR, "no matched value\n");
        goto cleanup;
    }
    pst_certificate_base->toBeSigned.region = pst_region;
    // 第 4 部分 第 6 小块 == SubjectAssurance_t *assuranceLevel 部分 ==
    pbs1_assurance_level = calloc(1, sizeof(SubjectAssurance_t));
    STOP_IT_IF_ERROR(NULL == pbs1_assurance_level, SubjectAssurance_t, "calloc failed\n");
    FILL_WITH_OCTET_STRING(*pbs1_assurance_level, redigits, 1, _ret);
    STOP_IT_IF_ERROR(0 != _ret, SubjectAssurance_t, "OCTET_STRING_fromBuf failed\n");
    pst_certificate_base->toBeSigned.assuranceLevel = pbs1_assurance_level;
    // 第 4 部分 第 7 小块 == struct SequenceOfPsidSsp *appPermissions 部分 ==
    pst_app_permissions = calloc(1, sizeof(struct SequenceOfPsidSsp));
    STOP_IT_IF_ERROR(NULL == pst_app_permissions, SequenceOfPsidSsp_t, "calloc failed\n");
    for (i = 0; i < SEQUENCE_OF_SIZE; i++) {
        if (NULL == ps_psid_ssp[i]) {
            ps_psid_ssp[i] = calloc(1, sizeof(struct PsidSsp));
            STOP_IT_IF_ERROR(NULL == ps_psid_ssp[i], PsidSsp_t, "calloc failed\n");
        }
        ps_psid_ssp[i]->psid = ul + i;
        ps_psid_ssp[i]->ssp = calloc(1, sizeof(struct ServiceSpecificPermissions));
        STOP_IT_IF_ERROR(NULL == ps_psid_ssp[i]->ssp, ServiceSpecificPermissions_t, "calloc failed\n");
        ps_psid_ssp[i]->ssp->present = (ServiceSpecificPermissions_PR_opaque + i) % 2 + 
                                                                            ServiceSpecificPermissions_PR_opaque;
        switch (ps_psid_ssp[i]->ssp->present) {
        case ServiceSpecificPermissions_PR_opaque:
            FILL_WITH_OCTET_STRING(ps_psid_ssp[i]->ssp->choice.opaque, ucsu256u, -1, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            break;
        case ServiceSpecificPermissions_PR_bitmapSsp:
            FILL_WITH_OCTET_STRING(ps_psid_ssp[i]->ssp->choice.bitmapSsp, digits, -1, _ret);
            STOP_IT_IF_ERROR(0 != _ret, BitmapSsp_t, "OCTET_STRING_fromBuf failed\n");
            break;
        default:
            LOG_ERR(ServiceSpecificPermissions_PR, "no matched value\n");
            goto cleanup;
        }
        _ret = asn_set_add(&pst_app_permissions->list, ps_psid_ssp[i]);
        STOP_IT_IF_ERROR(0 != _ret, ServiceSpecificPermissions_t, "asn_set_add failed\n");
    }
    pst_certificate_base->toBeSigned.appPermissions = pst_app_permissions;
    // 第 4 部分 第 8 小块 == struct SequenceOfPsidGroupPermissions *certIssuePermissions 部分 ==
    pst_cert_issue_permissions = calloc(1, sizeof(struct SequenceOfPsidGroupPermissions));
    STOP_IT_IF_ERROR(NULL == pst_cert_issue_permissions, SequenceOfPsidGroupPermissions_t, "calloc failed\n");
    for (i = 0; i < SEQUENCE_OF_SIZE; i++) {
        if (NULL == ps_psid_group_permissions[i]) {
            ps_psid_group_permissions[i] = calloc(1, sizeof(struct PsidGroupPermissions));
            STOP_IT_IF_ERROR(NULL == ps_psid_group_permissions[i], PsidGroupPermissions_t, "calloc failed\n");
        }
        ps_psid_group_permissions[i]->subjectPermissions.present = (SubjectPermissions_PR_explicit + i) % 2 +
                                                                            ServiceSpecificPermissions_PR_opaque;
        switch (ps_psid_group_permissions[i]->subjectPermissions.present) {
        case SubjectPermissions_PR_explicit:
            for (ii = 0; ii < Y_SIZE; ii++) {
                if (NULL == pss_psid_ssp_range[i][ii]) {
                    pss_psid_ssp_range[i][ii] = calloc(1, sizeof(struct PsidSspRange));
                    STOP_IT_IF_ERROR(NULL == pss_psid_ssp_range[i][ii], PsidSspRange_t, "calloc failed\n");
                }
                pss_psid_ssp_range[i][ii]->psid = ul + i + ii;
                if (NULL == pss_psid_ssp_range[i][ii]->sspRange) {
                    pss_psid_ssp_range[i][ii]->sspRange = calloc(1, sizeof(struct SspRange));
                    STOP_IT_IF_ERROR(NULL == pss_psid_ssp_range[i][ii]->sspRange, SspRange_t, "calloc failed\n");
                }
                pss_psid_ssp_range[i][ii]->sspRange->present = (SspRange_PR_opaque + i) % 3 + SspRange_PR_opaque;
                switch (pss_psid_ssp_range[i][ii]->sspRange->present) {
                case SspRange_PR_opaque:
                    for (iii = 0; iii < Z_SIZE; iii++) {
                        if (NULL == psss_octet_string[i][ii][iii]) {
                            psss_octet_string[i][ii][iii] = calloc(1, sizeof(struct OCTET_STRING));
                            STOP_IT_IF_ERROR(NULL == psss_octet_string[i][ii][iii], OCTET_STRING_t, "calloc failed\n");
                        }
                        // 很可能是这里的问题
                        FILL_WITH_OCTET_STRING(*psss_octet_string[i][ii][iii], ucsu256u, -1, _ret);
                        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                        // 危机还未解除
                        _ret = asn_set_add(&pss_psid_ssp_range[i][ii]->sspRange->choice.opaque.list, 
                                                                                        psss_octet_string[i][ii][iii]);
                        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "asn_set_add failed\n");
                    }
                    break;
                case SspRange_PR_all:
                    pss_psid_ssp_range[i][ii]->sspRange->choice.all = uinone;
                    break;
                case SspRange_PR_bitmapSspRange:
                    FILL_WITH_OCTET_STRING(pss_psid_ssp_range[i][ii]->sspRange->choice.bitmapSspRange.sspValue, 
                                                    ucsu64u, 32, _ret);
                    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                    FILL_WITH_OCTET_STRING(pss_psid_ssp_range[i][ii]->sspRange->choice.bitmapSspRange.sspBitmask, 
                                                    ucsu64u, 32, _ret);
                    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");   
                    break;
                default:
                    LOG_ERR(SspRange_PR, "no matched value\n");
                    goto cleanup;
                }
                _ret = asn_set_add(&ps_psid_group_permissions[i]->subjectPermissions.choice.Explicit.list,
                                                                                        pss_psid_ssp_range[i][ii]);
                STOP_IT_IF_ERROR(0 != _ret, PsidSspRange_t, "asn_set_add failed\n");
            }
            break;
        case SubjectPermissions_PR_all:
            ps_psid_group_permissions[i]->subjectPermissions.choice.all = uinone;
            break;
        default:
            LOG_ERR(SubjectPermissions_PR, "no matched value\n");
            goto cleanup;
        }
        
        if (NULL == ps_psid_group_permissions[i]->minChainLength) {
            ps_psid_group_permissions[i]->minChainLength = calloc(1, sizeof(long));
            STOP_IT_IF_ERROR(NULL == ps_psid_group_permissions[i]->minChainLength, long, "calloc failed\n");
        }
        *ps_psid_group_permissions[i]->minChainLength = i + 1;      // 缺省值为 1
        ps_psid_group_permissions[i]->chainLengthRange = i;         // 缺省值为 0
        
        if (NULL == ps_psid_group_permissions[i]->eeType) {     // 对比特串赋值
            ps_psid_group_permissions[i]->eeType =  calloc(1, sizeof(EndEntityType_t));
            STOP_IT_IF_ERROR(NULL == ps_psid_group_permissions[i]->eeType, EndEntityType_t, "calloc failed\n");
        }
        if (NULL == ps_psid_group_permissions[i]->eeType->buf) {
            ps_psid_group_permissions[i]->eeType->buf = calloc(1, 1);
            STOP_IT_IF_ERROR(NULL == ps_psid_group_permissions[i]->eeType->buf, uint8_t, "calloc failed\n");
        }
        ps_psid_group_permissions[i]->eeType->size = 1;
        ps_psid_group_permissions[i]->eeType->buf[0] |= 1 << (7 - EndEntityType_app);
        ps_psid_group_permissions[i]->eeType->buf[0] |= 1 << (7 - EndEntityType_enrol);
        ps_psid_group_permissions[i]->eeType->bits_unused = 6;
        
        _ret = asn_set_add(&pst_cert_issue_permissions->list, ps_psid_group_permissions[i]);
        STOP_IT_IF_ERROR(0 != _ret, PsidGroupPermissions_t, "asn_set_add failed\n");
    }
    pst_certificate_base->toBeSigned.certIssuePermissions = pst_cert_issue_permissions;
    // 第 4 部分 第 9 小块 == struct SequenceOfPsidGroupPermissions *certRequestPermissions 部分 ==
    pst_cert_request_permissions = calloc(1, sizeof(struct SequenceOfPsidGroupPermissions));
    STOP_IT_IF_ERROR(NULL == pst_cert_request_permissions, SequenceOfPsidGroupPermissions_t, "calloc failed\n");
    for (i = 0; i < SEQUENCE_OF_SIZE; i++) {
        if (NULL == ps_psid_group_permissions_t[i]) {
            ps_psid_group_permissions_t[i] = calloc(1, sizeof(struct PsidGroupPermissions));
            STOP_IT_IF_ERROR(NULL == ps_psid_group_permissions_t[i], PsidGroupPermissions_t, "calloc failed\n");
        }
        ps_psid_group_permissions_t[i]->subjectPermissions.present = (SubjectPermissions_PR_explicit + i) % 2 +
                                                                            ServiceSpecificPermissions_PR_opaque;
        switch (ps_psid_group_permissions_t[i]->subjectPermissions.present) {
        case SubjectPermissions_PR_explicit:
            for (ii = 0; ii < Y_SIZE; ii++) {
                if (NULL == pss_psid_ssp_range_t[i][ii]) {
                    pss_psid_ssp_range_t[i][ii] = calloc(1, sizeof(struct PsidSspRange));
                    STOP_IT_IF_ERROR(NULL == pss_psid_ssp_range_t[i][ii], PsidSspRange_t, "calloc failed");
                }
                pss_psid_ssp_range_t[i][ii]->psid = ul + i;
                if (NULL == pss_psid_ssp_range_t[i][ii]->sspRange) {
                    pss_psid_ssp_range_t[i][ii]->sspRange = calloc(1, sizeof(struct SspRange));
                    STOP_IT_IF_ERROR(NULL == pss_psid_ssp_range_t[i][ii], SspRange_t, "calloc failed\n");
                }
                pss_psid_ssp_range_t[i][ii]->sspRange->present = (SspRange_PR_opaque + i) % 3 + SspRange_PR_opaque;
                switch (pss_psid_ssp_range_t[i][ii]->sspRange->present) {
                case SspRange_PR_opaque:
                    for (iii = 0; iii < Z_SIZE; iii++) {
                        if (NULL == psss_octet_string_t[i][ii][iii]) {
                            psss_octet_string_t[i][ii][iii] = calloc(1, sizeof(struct OCTET_STRING));
                            STOP_IT_IF_ERROR(NULL == psss_octet_string_t[i][ii][iii], OCTET_STRING_t, "calloc failed\n");
                        }
                        FILL_WITH_OCTET_STRING(*psss_octet_string_t[i][ii][iii], ucsu256u, -1, _ret);
                        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                        _ret = asn_set_add(&pss_psid_ssp_range_t[i][ii]->sspRange->choice.opaque.list, 
                                                                                        psss_octet_string_t[i][ii][iii]);
                        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "asn_set_add failed\n");
                    }
                    break;
                case SspRange_PR_all:
                    pss_psid_ssp_range_t[i][ii]->sspRange->choice.all = uinone;
                    break;
                case SspRange_PR_bitmapSspRange:
                    FILL_WITH_OCTET_STRING(pss_psid_ssp_range_t[i][ii]->sspRange->choice.bitmapSspRange.sspValue, 
                                                    ucsu64u, 32, _ret);
                    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                    FILL_WITH_OCTET_STRING(pss_psid_ssp_range_t[i][ii]->sspRange->choice.bitmapSspRange.sspBitmask, 
                                                    ucsu64u, 32, _ret);
                    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");               
                    break;
                default:
                    LOG_ERR(SspRange_PR, "no matched value\n");
                    goto cleanup;
                }
                _ret = asn_set_add(&ps_psid_group_permissions_t[i]->subjectPermissions.choice.Explicit.list,
                                                                                    pss_psid_ssp_range_t[i][ii]);
                STOP_IT_IF_ERROR(0 != _ret, PsidSspRange_t, "asn_set_add failed\n");
            }
            break;
        case SubjectPermissions_PR_all:
            ps_psid_group_permissions_t[i]->subjectPermissions.choice.all = uinone;
            break;
        default:
            LOG_ERR(SubjectPermissions_PR, "no matched value\n");
            goto cleanup;
        }

        if (NULL == ps_psid_group_permissions_t[i]->minChainLength) {
            ps_psid_group_permissions_t[i]->minChainLength = calloc(1, sizeof(long));
            STOP_IT_IF_ERROR(NULL == ps_psid_group_permissions_t[i]->minChainLength, long, "calloc failed\n");
        }
        *ps_psid_group_permissions_t[i]->minChainLength = i + 1;        // 缺省值为 1
        ps_psid_group_permissions_t[i]->chainLengthRange = i;           // 缺省值为 0
        
        if (NULL == ps_psid_group_permissions_t[i]->eeType) {       // 对比特串赋值
            ps_psid_group_permissions_t[i]->eeType =  calloc(1, sizeof(EndEntityType_t));
            STOP_IT_IF_ERROR(NULL == ps_psid_group_permissions_t[i]->eeType, EndEntityType_t, "calloc failed\n");
        }
        if (NULL == ps_psid_group_permissions_t[i]->eeType->buf) {
            ps_psid_group_permissions_t[i]->eeType->buf = calloc(1, 1);
            STOP_IT_IF_ERROR(NULL == ps_psid_group_permissions_t[i]->eeType->buf, uint8_t, "calloc failed\n");
        }
        ps_psid_group_permissions_t[i]->eeType->size = 1;
        ps_psid_group_permissions_t[i]->eeType->buf[0] |= 1 << (7 - EndEntityType_app);
        ps_psid_group_permissions_t[i]->eeType->buf[0] |= 1 << (7 - EndEntityType_enrol);
        ps_psid_group_permissions_t[i]->eeType->bits_unused = 6;

        _ret = asn_set_add(&pst_cert_request_permissions->list, ps_psid_group_permissions_t[i]);
        STOP_IT_IF_ERROR(0 != _ret, PsidGroupPermissions_t, "asn_set_add failed\n");
    }
    pst_certificate_base->toBeSigned.certRequestPermissions = pst_cert_request_permissions;
    // 第 4 部分 第 10 小块 == NULL_t *canRequestRollover 部分 ==
    if (NULL == pi_can_request_rollover) {
        pi_can_request_rollover = calloc(1, sizeof(NULL_t));
        STOP_IT_IF_ERROR(NULL == pi_can_request_rollover, NULL_t, "calloc failed\n");
    }
    *pi_can_request_rollover = uinone;
    pst_certificate_base->toBeSigned.canRequestRollover = pi_can_request_rollover;
    // 第 4 部分 第 11 小块 == struct PublicEncryptionKey *encryptionKey 部分 ==
    pst_public_encryption_key = calloc(1, sizeof(struct PublicEncryptionKey));
    STOP_IT_IF_ERROR(NULL == pst_public_encryption_key, PublicEncryptionKey_t, "calloc failed\n");
    pst_public_encryption_key->supportedSymmAlg = SymmAlgorithm_aes128Ccm;
    pst_public_encryption_key->publicKey.present = BasePublicEncryptionKey_PR_eciesBrainpoolP256r1;
    switch (pst_public_encryption_key->publicKey.present) {
    case BasePublicEncryptionKey_PR_eciesNistP256:
        pst_public_encryption_key->publicKey.choice.eciesNistP256.present = EccP256CurvePoint_PR_x_only;
        switch (pst_public_encryption_key->publicKey.choice.eciesNistP256.present) {
        case EccP256CurvePoint_PR_x_only:
            FILL_WITH_OCTET_STRING(pst_public_encryption_key->publicKey.choice.eciesNistP256.choice.x_only, 
                                                                                            ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            break;
        case EccP256CurvePoint_PR_fill:
            pst_public_encryption_key->publicKey.choice.eciesNistP256.choice.fill = uinone;
            break;
        case EccP256CurvePoint_PR_compressed_y_0:
            FILL_WITH_OCTET_STRING(pst_public_encryption_key->publicKey.choice.eciesNistP256.choice.compressed_y_0,
                                                                                                ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            break;
        case EccP256CurvePoint_PR_compressed_y_1:
            FILL_WITH_OCTET_STRING(pst_public_encryption_key->publicKey.choice.eciesNistP256.choice.compressed_y_1,
                                                                                                ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");   
            break;
        case EccP256CurvePoint_PR_uncompressedP256:
            FILL_WITH_OCTET_STRING(pst_public_encryption_key->publicKey.choice.eciesNistP256.choice.uncompressedP256.x,
                                                                                                ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            FILL_WITH_OCTET_STRING(pst_public_encryption_key->publicKey.choice.eciesNistP256.choice.uncompressedP256.y,
                                                                                                ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            break;
        default:
            LOG_ERR(EccP256CurvePoint_PR, "no matched value\n");
            goto cleanup;           
        }
        break;
    case BasePublicEncryptionKey_PR_eciesBrainpoolP256r1:
        pst_public_encryption_key->publicKey.choice.eciesBrainpoolP256r1.present = EccP256CurvePoint_PR_compressed_y_0;
        switch (pst_public_encryption_key->publicKey.choice.eciesBrainpoolP256r1.present) {
        case EccP256CurvePoint_PR_x_only:
            FILL_WITH_OCTET_STRING(pst_public_encryption_key->publicKey.choice.eciesBrainpoolP256r1.choice.x_only, 
                                                                                            ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            break;
        case EccP256CurvePoint_PR_fill:
            pst_public_encryption_key->publicKey.choice.eciesBrainpoolP256r1.choice.fill = uinone;
            break;
        case EccP256CurvePoint_PR_compressed_y_0:
            FILL_WITH_OCTET_STRING(
                    pst_public_encryption_key->publicKey.choice.eciesBrainpoolP256r1.choice.compressed_y_0,
                                                                                            ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            break;
        case EccP256CurvePoint_PR_compressed_y_1:
            FILL_WITH_OCTET_STRING(
                    pst_public_encryption_key->publicKey.choice.eciesBrainpoolP256r1.choice.compressed_y_1,
                                                                                                ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");   
            break;
        case EccP256CurvePoint_PR_uncompressedP256:
            FILL_WITH_OCTET_STRING(
                    pst_public_encryption_key->publicKey.choice.eciesBrainpoolP256r1.choice.uncompressedP256.x,
                                                                                            ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            FILL_WITH_OCTET_STRING(
                    pst_public_encryption_key->publicKey.choice.eciesBrainpoolP256r1.choice.uncompressedP256.y,
                                                                                            ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            break;
        default:
            LOG_ERR(EccP256CurvePoint_PR, "no matched value\n");
            goto cleanup;           
        }   
        break;
    default:
        LOG_ERR(BasePublicEncryptionKey_PR, "no matched value\n");
        goto cleanup;
    }
    pst_certificate_base->toBeSigned.encryptionKey = pst_public_encryption_key;
    // 第 4 部分 第 12 小块 == VerificationKeyIndicator_t verifyKeyIndicator 部分 ==
    pst_certificate_base->toBeSigned.verifyKeyIndicator.present = VerificationKeyIndicator_PR_verificationKey;  // 再一个1
    switch (pst_certificate_base->toBeSigned.verifyKeyIndicator.present) {
    case VerificationKeyIndicator_PR_verificationKey:
        pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.present = 
                                                                        PublicVerificationKey_PR_ecdsaNistP256; // 再一个2
        switch (pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.present) {
        case PublicVerificationKey_PR_ecdsaNistP256:
            pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.present = 
                                                                                EccP256CurvePoint_PR_x_only;    // 再一个3
            switch (pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.present) {
                case EccP256CurvePoint_PR_x_only:
                    FILL_WITH_OCTET_STRING(
                        pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.choice.x_only,
                                                                                            ucsu64u, 32, _ret);
                    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                    break;
                case EccP256CurvePoint_PR_fill:
                    pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.choice.fill = uinone;
                    break;
                case EccP256CurvePoint_PR_compressed_y_0:
                    FILL_WITH_OCTET_STRING(
                        pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.choice.compressed_y_0,
                                                                                            ucsu64u, 32, _ret);
                    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                    break;
                case EccP256CurvePoint_PR_compressed_y_1:
                    FILL_WITH_OCTET_STRING(
                        pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.choice.compressed_y_1,
                                                                                            ucsu64u, 32, _ret);
                    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                    break;
                case EccP256CurvePoint_PR_uncompressedP256:
                    FILL_WITH_OCTET_STRING(
                        pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.choice.uncompressedP256.x,
                                                                                            ucsu64u, 32, _ret);
                    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                    FILL_WITH_OCTET_STRING(
                        pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.choice.uncompressedP256.y,
                                                                                            ucsu64u, 32, _ret);
                    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                    break;
                default:
                    LOG_ERR(EccP256CurvePoint_PR, "no matched value\n");
                    goto cleanup;
            }
            break;
        case PublicVerificationKey_PR_ecdsaBrainpoolP256r1:
            pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaBrainpoolP256r1.present =
                                                                                            EccP256CurvePoint_PR_x_only;
            switch (pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaBrainpoolP256r1.present) {
            case EccP256CurvePoint_PR_x_only:
                FILL_WITH_OCTET_STRING(
                    pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaBrainpoolP256r1.choice.x_only,
                                                                                            ucsu64u, 32, _ret);
                STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                break;
            case EccP256CurvePoint_PR_fill:
                    pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaBrainpoolP256r1.choice.fill = uinone;
                break;
            case EccP256CurvePoint_PR_compressed_y_0:
                    FILL_WITH_OCTET_STRING(
                        pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaBrainpoolP256r1.choice.compressed_y_0,
                                                                                            ucsu64u, 32, _ret);
                    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                break;
            case EccP256CurvePoint_PR_compressed_y_1:
                    FILL_WITH_OCTET_STRING(
                        pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaBrainpoolP256r1.choice.compressed_y_1,
                                                                                            ucsu64u, 32, _ret);
                    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                break;
            case EccP256CurvePoint_PR_uncompressedP256:
                    FILL_WITH_OCTET_STRING(
                        pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaBrainpoolP256r1.choice.uncompressedP256.x,
                                                                                            ucsu64u, 32, _ret);
                    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                    FILL_WITH_OCTET_STRING(
                        pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaBrainpoolP256r1.choice.uncompressedP256.y,
                                                                                            ucsu64u, 32, _ret);
                    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                break;
            default:
                LOG_ERR(EccP256CurvePoint_PR, "no matched value\n");
                goto cleanup;
            }
            break;
        case PublicVerificationKey_PR_ecdsaBrainpoolP384r1:
            pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaBrainpoolP384r1.present =
                                                                                            EccP384CurvePoint_PR_x_only;
            switch (pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaBrainpoolP384r1.present) {
            case EccP384CurvePoint_PR_x_only:
                FILL_WITH_OCTET_STRING(
                    pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaBrainpoolP384r1.choice.x_only,
                                                                                            ucsu64u, 48, _ret);
                STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                break;
            case EccP384CurvePoint_PR_fill:
                    pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaBrainpoolP384r1.choice.fill = uinone;
                break;
            case EccP384CurvePoint_PR_compressed_y_0:
                    FILL_WITH_OCTET_STRING(
                        pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaBrainpoolP384r1.choice.compressed_y_0,
                                                                                            ucsu64u, 48, _ret);
                    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                break;
            case EccP384CurvePoint_PR_compressed_y_1:
                    FILL_WITH_OCTET_STRING(
                        pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaBrainpoolP384r1.choice.compressed_y_1,
                                                                                            ucsu64u, 48, _ret);
                    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                break;
            case EccP384CurvePoint_PR_uncompressedP384:
                    FILL_WITH_OCTET_STRING(
                        pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaBrainpoolP384r1.choice.uncompressedP384.x,
                                                                                            ucsu64u, 48, _ret);
                    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                    FILL_WITH_OCTET_STRING(
                        pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaBrainpoolP384r1.choice.uncompressedP384.y,
                                                                                            ucsu64u, 48, _ret);
                    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                break;
            default:
                LOG_ERR(EccP384CurvePoint_PR, "no matched value\n");
                goto cleanup;
            }                       
            break;
        default:
            LOG_ERR(PublicVerificationKey_PR, "no matched value\n");
            goto cleanup;
        }
        break;
    case VerificationKeyIndicator_PR_reconstructionValue:
        pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.reconstructionValue.present = 
                                                                            EccP256CurvePoint_PR_x_only;    
        switch (pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.reconstructionValue.present) {
        case EccP256CurvePoint_PR_x_only:
            FILL_WITH_OCTET_STRING(
                pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.reconstructionValue.choice.x_only,
                                                                                            ucsu64u, 32, _ret); 
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            break;
        case EccP256CurvePoint_PR_fill:
            pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.reconstructionValue.choice.fill = uinone;
            break;
        case EccP256CurvePoint_PR_compressed_y_0:
            FILL_WITH_OCTET_STRING(
                pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.reconstructionValue.choice.compressed_y_0,
                                                                                    ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            break;
        case EccP256CurvePoint_PR_compressed_y_1:
            FILL_WITH_OCTET_STRING(
                pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.reconstructionValue.choice.compressed_y_1,
                                                                                    ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");   
            break;
        case EccP256CurvePoint_PR_uncompressedP256:
            FILL_WITH_OCTET_STRING(
                pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.reconstructionValue.choice.uncompressedP256.x,
                                                                                    ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            FILL_WITH_OCTET_STRING(
                pst_certificate_base->toBeSigned.verifyKeyIndicator.choice.reconstructionValue.choice.uncompressedP256.y,
                                                                                    ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            break;
        default:
            LOG_ERR(EccP256CurvePoint_PR, "no matched value\n");
            goto cleanup;
        }
        break;
    default:
        LOG_ERR(VerificationKeyIndicator_PR, "no matched value\n");
        goto cleanup;
    }
    // 第 5 部分
    pst_signature = calloc(1, sizeof(struct Signature));
    STOP_IT_IF_ERROR(NULL == pst_signature, NULL_t, "calloc failed\n");
    pst_signature->present = Signature_PR_ecdsaNistP256Signature;
    switch (pst_signature->present) {
    case Signature_PR_ecdsaNistP256Signature:
        pst_signature->choice.ecdsaNistP256Signature.rSig.present = EccP256CurvePoint_PR_x_only;
        switch (pst_signature->choice.ecdsaNistP256Signature.rSig.present) {
        case EccP256CurvePoint_PR_x_only:
            FILL_WITH_OCTET_STRING(pst_signature->choice.ecdsaNistP256Signature.rSig.choice.x_only, 
                                                                                    ucsu64u, 32, _ret); 
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            break;
        case EccP256CurvePoint_PR_fill:
            pst_signature->choice.ecdsaNistP256Signature.rSig.choice.fill = uinone;
            break;
        case EccP256CurvePoint_PR_compressed_y_0:
            FILL_WITH_OCTET_STRING(
                    pst_signature->choice.ecdsaNistP256Signature.rSig.choice.compressed_y_0, 
                                                                                    ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            break;
        case EccP256CurvePoint_PR_compressed_y_1:
            FILL_WITH_OCTET_STRING(
                    pst_signature->choice.ecdsaNistP256Signature.rSig.choice.compressed_y_1, 
                                                                                    ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");   
            break;
        case EccP256CurvePoint_PR_uncompressedP256:
            FILL_WITH_OCTET_STRING(
                    pst_signature->choice.ecdsaNistP256Signature.rSig.choice.uncompressedP256.x, 
                                                                                        ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            FILL_WITH_OCTET_STRING(
                    pst_signature->choice.ecdsaNistP256Signature.rSig.choice.uncompressedP256.y, 
                                                                                        ucsu256u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            break;
        default:
            LOG_ERR(EccP256CurvePoint_PR, "no matched value\n");
            goto cleanup;
        }
        FILL_WITH_OCTET_STRING(pst_signature->choice.ecdsaNistP256Signature.sSig, ucsu64u, 32, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        break;
    case Signature_PR_ecdsaBrainpoolP256r1Signature:
        pst_signature->choice.ecdsaBrainpoolP256r1Signature.rSig.present = EccP256CurvePoint_PR_x_only;
        switch (pst_signature->choice.ecdsaBrainpoolP256r1Signature.rSig.present) {
        case EccP256CurvePoint_PR_x_only:
            FILL_WITH_OCTET_STRING(
                    pst_signature->choice.ecdsaBrainpoolP256r1Signature.rSig.choice.x_only, 
                                                                                    ucsu64u, 32, _ret); 
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            break;
        case EccP256CurvePoint_PR_fill:
            pst_signature->choice.ecdsaBrainpoolP256r1Signature.rSig.choice.fill = uinone;
            break;
        case EccP256CurvePoint_PR_compressed_y_0:
            FILL_WITH_OCTET_STRING(
                    pst_signature->choice.ecdsaBrainpoolP256r1Signature.rSig.choice.compressed_y_0, 
                                                                                    ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            break;
        case EccP256CurvePoint_PR_compressed_y_1:
            FILL_WITH_OCTET_STRING(
                    pst_signature->choice.ecdsaBrainpoolP256r1Signature.rSig.choice.compressed_y_1, 
                                                                                    ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");   
            break;
        case EccP256CurvePoint_PR_uncompressedP256:
            FILL_WITH_OCTET_STRING(
                    pst_signature->choice.ecdsaBrainpoolP256r1Signature.rSig.choice.uncompressedP256.x, 
                                                                                        ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            FILL_WITH_OCTET_STRING(
                    pst_signature->choice.ecdsaBrainpoolP256r1Signature.rSig.choice.uncompressedP256.y, 
                                                                                        ucsu64u, 32, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            break;
        default:
            LOG_ERR(EccP256CurvePoint_PR, "no matched value\n");
            goto cleanup;
        }
        FILL_WITH_OCTET_STRING(pst_signature->choice.ecdsaBrainpoolP256r1Signature.sSig, ucsu64u, 32, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        break;
    case Signature_PR_ecdsaBrainpoolP384r1Signature:
        pst_signature->choice.ecdsaBrainpoolP384r1Signature.rSig.present = EccP256CurvePoint_PR_x_only;
        switch (pst_signature->choice.ecdsaBrainpoolP384r1Signature.rSig.present) {
        case EccP384CurvePoint_PR_x_only:
            FILL_WITH_OCTET_STRING(
                    pst_signature->choice.ecdsaBrainpoolP384r1Signature.rSig.choice.x_only, 
                                                                                    ucsu64u, 48, _ret); 
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            break;
        case EccP384CurvePoint_PR_fill:
            pst_signature->choice.ecdsaBrainpoolP384r1Signature.rSig.choice.fill = uinone;
            break;
        case EccP384CurvePoint_PR_compressed_y_0:
            FILL_WITH_OCTET_STRING(
                        pst_signature->choice.ecdsaBrainpoolP384r1Signature.rSig.choice.compressed_y_0, 
                                                                                        ucsu64u, 48, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            break;
        case EccP384CurvePoint_PR_compressed_y_1:
            FILL_WITH_OCTET_STRING(
                    pst_signature->choice.ecdsaBrainpoolP384r1Signature.rSig.choice.compressed_y_1, 
                                                                                    ucsu64u, 48, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");   
            break;
        case EccP384CurvePoint_PR_uncompressedP384:
            FILL_WITH_OCTET_STRING(
                pst_signature->choice.ecdsaBrainpoolP384r1Signature.rSig.choice.uncompressedP384.x, 
                                                                                    ucsu64u, 48, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            FILL_WITH_OCTET_STRING(
                    pst_signature->choice.ecdsaBrainpoolP384r1Signature.rSig.choice.uncompressedP384.y, 
                                                                                    ucsu64u, 48, _ret);
            STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            break;
        default:
            LOG_ERR(EccP384CurvePoint_PR, "no matched value\n");
            goto cleanup;
        }
        FILL_WITH_OCTET_STRING(pst_signature->choice.ecdsaBrainpoolP384r1Signature.sSig, ucsu64u, 48, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        break;
    default:
        LOG_ERR(Signature_PR, "no matched value\n");
        goto cleanup;
    }
    pst_certificate_base->signature = pst_signature;
        
    // 编码
    ec = oer_encode(&asn_DEF_CertificateBase, pst_certificate_base, write_callback, (void*)fp);
    if (1 == ec.encoded) {
        fprintf(stderr, "%d ecode(%d): %s\n", __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
        goto cleanup;
    }

    // xml 格式打印
    xer_fprint(stdout, &asn_DEF_CertificateBase, pst_certificate_base);
    printf("\n");
    
    RET = 0;
cleanup:
    if (0 == RET) fprintf(stdout, "=== encode success ===\n");
    else fprintf(stdout, "failed\n");
    
    if (fp) fclose(fp);
    
    ASN_STRUCT_FREE(asn_DEF_CertificateBase, pst_certificate_base);
    
    if (0 == RET) fprintf(stdout, "==== free success ====\n");
    return RET;
}
