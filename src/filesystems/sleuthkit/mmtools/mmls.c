/*
 * The Sleuth Kit
 *
 * $Date: 2006/12/07 16:38:18 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2006 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
 *
 * mmls - list media management structure contents
 *
 *
 * This software is distributed under the Common Public License 1.0
 *
 */

#include "mm_tools.h"


static TSK_TCHAR *progname;

static uint8_t print_bytes = 0;
static uint8_t recurse = 0;

static int recurse_cnt = 0;
static DADDR_T recurse_list[64];

void
usage()
{
    TFPRINTF(stderr,
	_TSK_T
	("%s [-i imgtype] [-o imgoffset] [-brvV] [-t mmtype] image [images]\n"),
	progname);
    tsk_fprintf(stderr,
	"\t-t mmtype: The type of partition system (use '-t list' for list of supported types)\n");
    tsk_fprintf(stderr,
	"\t-i imgtype: The format of the image file (use '-i list' for list supported types)\n");
    tsk_fprintf(stderr,
	"\t-o imgoffset: Offset to the start of the volume that contains the partition system (in sectors)\n");
    tsk_fprintf(stderr, "\t-b: print the rounded length in bytes\n");
    tsk_fprintf(stderr,
	"\t-r: recurse and look for other partition tables in partitions (DOS Only)\n");
    tsk_fprintf(stderr, "\t-v: verbose output\n");
    tsk_fprintf(stderr, "\t-V: print the version\n");
    exit(1);
}

/*
 * The callback action for the part_walk
 *
 * Prints the layout information
 * */
uint8_t
part_act(MM_INFO * mm, PNUM_T pnum, MM_PART * part, int flag, void *ptr)
{
    /* Neither table or slot were given */
    if ((part->table_num == -1) && (part->slot_num == -1))
	tsk_printf("%.2" PRIuPNUM ":  -----   ", pnum);

    /* Table was not given, but slot was */
    else if ((part->table_num == -1) && (part->slot_num != -1))
	tsk_printf("%.2" PRIuPNUM ":  %.2" PRIu8 "      ",
	    pnum, part->slot_num);

    /* The Table was given, but slot wasn't */
    else if ((part->table_num != -1) && (part->slot_num == -1))
	tsk_printf("%.2" PRIuPNUM ":  -----   ", pnum);

    /* Both table and slot were given */
    else if ((part->table_num != -1) && (part->slot_num != -1))
	tsk_printf("%.2" PRIuPNUM ":  %.2d:%.2d   ",
	    pnum, part->table_num, part->slot_num);

    if (print_bytes) {
	OFF_T size;
	char unit = ' ';
	size = part->len;

	if (part->len < 2) {
	    size = 512 * part->len;
	    unit = 'B';
	}
	else if (size < (2 << 10)) {
	    size = part->len / 2;
	    unit = 'K';
	}
	else if (size < (2 << 20)) {
	    size = part->len / (2 << 10);
	    unit = 'M';
	}
	else if (size < ((OFF_T) 2 << 30)) {
	    size = part->len / (2 << 20);
	    unit = 'G';
	}
	else if (size < ((OFF_T) 2 << 40)) {
	    size = part->len / (2 << 30);
	    unit = 'T';
	}

	/* Print the layout */
	tsk_printf("%.10" PRIuDADDR "   %.10" PRIuDADDR "   %.10" PRIuDADDR
	    "   %.4" PRIuOFF "%c   %s\n", part->start,
	    (DADDR_T) (part->start + part->len - 1), part->len, size, unit,
	    part->desc);
    }
    else {

	/* Print the layout */
	tsk_printf("%.10" PRIuDADDR "   %.10" PRIuDADDR "   %.10" PRIuDADDR
	    "   %s\n", part->start,
	    (DADDR_T) (part->start + part->len - 1), part->len,
	    part->desc);
    }

    if ((recurse) && (mm->mmtype == MM_DOS) && (part->type == MM_TYPE_VOL)) {
	// @@@ This assumes 512-byte sectors
	if (recurse_cnt < 64)
	    recurse_list[recurse_cnt++] = part->start * 512;
    }

    return WALK_CONT;
}

static void
print_header(MM_INFO * mm)
{
    tsk_printf("%s\n", mm->str_type);
    tsk_printf("Offset Sector: %" PRIuDADDR "\n",
	(DADDR_T) (mm->offset / mm->block_size));
    tsk_printf("Units are in %d-byte sectors\n\n", mm->block_size);
    if (print_bytes)
	tsk_printf
	    ("     Slot    Start        End          Length       Size    Description\n");
    else
	tsk_printf
	    ("     Slot    Start        End          Length       Description\n");
}


int
MAIN(int argc, TSK_TCHAR ** argv)
{
    MM_INFO *mm;
    TSK_TCHAR *mmtype = NULL;
    int ch;
    SSIZE_T imgoff = 0;
    uint8_t flags = 0;
    TSK_TCHAR *imgtype = NULL;
    IMG_INFO *img;

    progname = argv[0];

    while ((ch = getopt(argc, argv, _TSK_T("bi:o:rt:vV"))) > 0) {
	switch (ch) {
	case _TSK_T('b'):
	    print_bytes = 1;
	    break;
	case _TSK_T('i'):
	    imgtype = optarg;
	    if (TSTRCMP(imgtype, _TSK_T("list")) == 0) {
		img_print_types(stderr);
		exit(1);
	    }

	    break;

	case _TSK_T('o'):
	    if ((imgoff = parse_offset(optarg)) == -1) {
		tsk_error_print(stderr);
		exit(1);
	    }
	    break;
	case _TSK_T('r'):
	    recurse = 1;
	    break;
	case _TSK_T('t'):
	    mmtype = optarg;
	    if (TSTRCMP(mmtype, _TSK_T("list")) == 0) {
		mm_print_types(stderr);
		exit(1);
	    }

	    break;
	case _TSK_T('v'):
	    verbose++;
	    break;
	case _TSK_T('V'):
	    print_version(stdout);
	    exit(0);
	case _TSK_T('?'):
	default:
	    tsk_fprintf(stderr, "Unknown argument\n");
	    usage();
	}
    }

    /* We need at least one more argument */
    if (optind >= argc) {
	tsk_fprintf(stderr, "Missing image name\n");
	usage();
    }

    /* open the image */
    img =
	img_open(imgtype, argc - optind,
	(const TSK_TCHAR **) &argv[optind]);

    if (img == NULL) {
	tsk_error_print(stderr);
	exit(1);
    }

    /* process the partition tables */
    mm = mm_open(img, (OFF_T) imgoff, mmtype);
    if (mm == NULL) {
	tsk_error_print(stderr);
	if (tsk_errno == TSK_ERR_MM_UNSUPTYPE)
	    mm_print_types(stderr);
	exit(1);
    }

    print_header(mm);

    if (mm->part_walk(mm, mm->first_part, mm->last_part, flags,
	    part_act, NULL)) {
	tsk_error_print(stderr);
	mm->close(mm);
	exit(1);
    }

    mm->close(mm);
    if ((recurse) && (mm->mmtype == MM_DOS)) {
	int i;
	/* disable recursing incase we hit another DOS partition
	 * future versions may support more layers */
	recurse = 0;

	for (i = 0; i < recurse_cnt; i++) {
	    mm = mm_open(img, recurse_list[i], NULL);
	    if (mm != NULL) {
		tsk_printf("\n\n");
		print_header(mm);
		if (mm->part_walk(mm, mm->first_part, mm->last_part, flags,
			part_act, NULL)) {
		    tsk_error_reset();
		}
		mm->close(mm);
	    }
	    else {
		/* Ignore error in this case and reset */
		tsk_error_reset();
	    }
	}
    }

    img->close(img);
    exit(0);
}
