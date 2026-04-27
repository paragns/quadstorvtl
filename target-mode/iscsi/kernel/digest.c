/*
 * iSCSI digest handling - updated for kernel 4.6+ crypto_shash API
 */

#include "iscsi.h"
#include "digest.h"
#include "iscsi_dbg.h"
#include "scdefs.h"

void digest_alg_available(unsigned int *val)
{
#ifdef LINUX
if (*val & DIGEST_CRC32C && !crypto_has_alg("crc32c", 0, CRYPTO_ALG_ASYNC)) {
printk("CRC32C digest algorithm not available in kernel\n");
*val |= ~DIGEST_CRC32C;
}
#endif
}

#ifdef LINUX
int digest_init(struct iscsi_conn *conn)
{
int err = 0;

if (!(conn->hdigest_type & DIGEST_ALL))
conn->hdigest_type = DIGEST_NONE;

if (!(conn->ddigest_type & DIGEST_ALL))
conn->ddigest_type = DIGEST_NONE;

if (conn->hdigest_type & DIGEST_CRC32C ||
    conn->ddigest_type & DIGEST_CRC32C) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
conn->rx_hash = crypto_alloc_shash("crc32c", 0, 0);
if (IS_ERR(conn->rx_hash)) {
conn->rx_hash = NULL;
err = -ENOMEM;
goto out;
}
conn->tx_hash = crypto_alloc_shash("crc32c", 0, 0);
if (IS_ERR(conn->tx_hash)) {
conn->tx_hash = NULL;
err = -ENOMEM;
goto out;
}
#else
conn->rx_hash.tfm = crypto_alloc_hash("crc32c", 0, CRYPTO_ALG_ASYNC);
conn->rx_hash.flags = 0;
if (IS_ERR(conn->rx_hash.tfm)) {
conn->rx_hash.tfm = NULL;
err = -ENOMEM;
goto out;
}
conn->tx_hash.tfm = crypto_alloc_hash("crc32c", 0, CRYPTO_ALG_ASYNC);
conn->tx_hash.flags = 0;
if (IS_ERR(conn->tx_hash.tfm)) {
conn->tx_hash.tfm = NULL;
err = -ENOMEM;
goto out;
}
#endif
}
out:
if (err)
digest_cleanup(conn);
return err;
}

void digest_cleanup(struct iscsi_conn *conn)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
if (conn->tx_hash)
crypto_free_shash(conn->tx_hash);
if (conn->rx_hash)
crypto_free_shash(conn->rx_hash);
#else
if (conn->tx_hash.tfm)
crypto_free_hash(conn->tx_hash.tfm);
if (conn->rx_hash.tfm)
crypto_free_hash(conn->rx_hash.tfm);
#endif
}
#else
int digest_init(struct iscsi_conn *conn)
{
if (!(conn->hdigest_type & DIGEST_ALL))
conn->hdigest_type = DIGEST_NONE;
if (!(conn->ddigest_type & DIGEST_ALL))
conn->ddigest_type = DIGEST_NONE;
return 0;
}
void digest_cleanup(struct iscsi_conn *conn) {}
#endif

static inline void __dbg_simulate_header_digest_error(struct iscsi_cmnd *cmnd) {}
static inline void __dbg_simulate_data_digest_error(struct iscsi_cmnd *cmnd) {}

#ifdef LINUX
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
static void digest_header(struct crypto_shash *hash, struct iscsi_pdu *pdu, u8 *crc)
{
SHASH_DESC_ON_STACK(desc, hash);
desc->tfm = hash;
crypto_shash_init(desc);
crypto_shash_update(desc, (u8 *)&pdu->bhs, sizeof(struct iscsi_hdr));
if (pdu->ahssize)
crypto_shash_update(desc, (u8 *)pdu->ahs, pdu->ahssize);
crypto_shash_final(desc, crc);
}

static void digest_data(struct crypto_shash *hash, struct iscsi_cmnd *cmnd,
struct tio *tio, u32 offset, u8 *crc)
{
SHASH_DESC_ON_STACK(desc, hash);
desc->tfm = hash;
u32 size, length;
int i, idx;

size = cmnd->pdu.datasize;
size = (size + 3) & ~3;
offset += tio->offset;
idx = offset >> PAGE_SHIFT;
offset &= ~PAGE_MASK;

crypto_shash_init(desc);
for (i = 0; size; i++) {
void *addr;
if (offset + size > PAGE_SIZE)
length = PAGE_SIZE - offset;
else
length = size;
addr = page_address(tio->pvec[idx + i]);
crypto_shash_update(desc, (u8 *)addr + offset, length);
size -= length;
offset = 0;
}
crypto_shash_final(desc, crc);
}
#else
static void digest_header(struct hash_desc *hash, struct iscsi_pdu *pdu, u8 *crc)
{
struct scatterlist sg[2];
unsigned int nbytes = sizeof(struct iscsi_hdr);

sg_init_table(sg, pdu->ahssize ? 2 : 1);
sg_set_buf(&sg[0], &pdu->bhs, nbytes);
if (pdu->ahssize) {
sg_set_buf(&sg[1], pdu->ahs, pdu->ahssize);
nbytes += pdu->ahssize;
}
crypto_hash_init(hash);
crypto_hash_update(hash, sg, nbytes);
crypto_hash_final(hash, crc);
}

static void digest_data(struct hash_desc *hash, struct iscsi_cmnd *cmnd,
struct tio *tio, u32 offset, u8 *crc)
{
struct scatterlist *sg = cmnd->conn->hash_sg;
u32 size, length;
int i, idx, count;
unsigned int nbytes;

size = cmnd->pdu.datasize;
nbytes = size = (size + 3) & ~3;
offset += tio->offset;
idx = offset >> PAGE_SHIFT;
offset &= ~PAGE_MASK;
count = get_pgcnt(size, offset);
assert(idx + count <= tio->pg_cnt);
assert(count <= ISCSI_CONN_IOV_MAX);

sg_init_table(sg, ARRAY_SIZE(cmnd->conn->hash_sg));
crypto_hash_init(hash);
for (i = 0; size; i++) {
if (offset + size > PAGE_SIZE)
length = PAGE_SIZE - offset;
else
length = size;
sg_set_page(&sg[i], tio->pvec[idx + i], length, offset);
size -= length;
offset = 0;
}
sg_mark_end(&sg[i - 1]);
crypto_hash_update(hash, sg, nbytes);
crypto_hash_final(hash, crc);
}
#endif

int digest_rx_header(struct iscsi_cmnd *cmnd)
{
u32 crc;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
digest_header(cmnd->conn->rx_hash, &cmnd->pdu, (u8 *)&crc);
#else
digest_header(&cmnd->conn->rx_hash, &cmnd->pdu, (u8 *)&crc);
#endif
if (crc != cmnd->hdigest)
return -EIO;
return 0;
}

void digest_tx_header(struct iscsi_cmnd *cmnd)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
digest_header(cmnd->conn->tx_hash, &cmnd->pdu, (u8 *)&cmnd->hdigest);
#else
digest_header(&cmnd->conn->tx_hash, &cmnd->pdu, (u8 *)&cmnd->hdigest);
#endif
}

int digest_rx_data(struct iscsi_cmnd *cmnd)
{
struct tio *tio;
struct iscsi_cmnd *scsi_cmnd;
struct iscsi_data_out_hdr *req;
u32 offset, crc;

switch (cmnd_opcode(cmnd)) {
case ISCSI_OP_SCSI_REJECT:
case ISCSI_OP_PDU_REJECT:
case ISCSI_OP_DATA_REJECT:
return 0;
case ISCSI_OP_SCSI_DATA_OUT:
scsi_cmnd = cmnd->req;
req = (struct iscsi_data_out_hdr *)&cmnd->pdu.bhs;
tio = scsi_cmnd->tio;
offset = be32_to_cpu(req->buffer_offset);
break;
default:
tio = cmnd->tio;
offset = 0;
}

if (cmnd->conn->read_ctio) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
digest_read_ctio(cmnd->conn->rx_hash, cmnd, cmnd->conn->read_ctio, (u8 *)&crc);
#else
digest_read_ctio(&cmnd->conn->rx_hash, cmnd, cmnd->conn->read_ctio, (u8 *)&crc);
#endif
} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
digest_data(cmnd->conn->rx_hash, cmnd, tio, offset, (u8 *)&crc);
#else
digest_data(&cmnd->conn->rx_hash, cmnd, tio, offset, (u8 *)&crc);
#endif
}

if (!cmnd->conn->read_overflow &&
    (cmnd_opcode(cmnd) != ISCSI_OP_PDU_REJECT)) {
if (crc != cmnd->ddigest)
return -EIO;
}
return 0;
}

void digest_tx_data(struct iscsi_cmnd *cmnd)
{
struct tio *tio = cmnd->tio;
struct iscsi_data_out_hdr *req = (struct iscsi_data_out_hdr *)&cmnd->pdu.bhs;

if (cmnd->ctio) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
digest_write_ctio(cmnd->conn->tx_hash, cmnd, cmnd->ctio, (u8 *)&cmnd->ddigest);
#else
digest_write_ctio(&cmnd->conn->tx_hash, cmnd, cmnd->ctio, (u8 *)&cmnd->ddigest);
#endif
} else {
assert(tio);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
digest_data(cmnd->conn->tx_hash, cmnd, tio,
    be32_to_cpu(req->buffer_offset), (u8 *)&cmnd->ddigest);
#else
digest_data(&cmnd->conn->tx_hash, cmnd, tio,
    be32_to_cpu(req->buffer_offset), (u8 *)&cmnd->ddigest);
#endif
}
}
#else
int digest_rx_header(struct iscsi_cmnd *cmnd) { return 0; }
void digest_tx_header(struct iscsi_cmnd *cmnd) {}
int digest_rx_data(struct iscsi_cmnd *cmnd) { return 0; }
void digest_tx_data(struct iscsi_cmnd *cmnd) {}
#endif
