/*
 * $Id: rfc1876.c,v 1.2 2002/09/09 10:59:15 alexis Exp $
 *
 * rfc1876.c -- LOC record conversion routines taken from RFC1876
 *
 * This code is not copyrighted.
 *
 */
#include "config.h"

#include <sys/types.h>
#include <sys/param.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * routines to convert between on-the-wire RR format and zone file
 * format.  Does not contain conversion to/from decimal degrees;
 * divide or multiply by 60*60*1000 for that.
 */

static unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
                                 1000000,10000000,100000000,1000000000};

/* takes an XeY precision/size value, returns a string representation.*/
static const char *
precsize_ntoa(prec)
        u_int8_t prec;
{
        static char retbuf[sizeof("90000000.00")];
        unsigned long val;
        int mantissa, exponent;

        mantissa = (int)((prec >> 4) & 0x0f) % 10;
        exponent = (int)((prec >> 0) & 0x0f) % 10;

        val = mantissa * poweroften[exponent];

        (void) sprintf(retbuf,"%d.%.2d", val/100, val%100);
        return (retbuf);
}

/* converts ascii size/precision X * 10**Y(cm) to 0xXY. moves pointer.*/
static u_int8_t
precsize_aton(strptr)
        char **strptr;
{
        unsigned int mval = 0, cmval = 0;
        u_int8_t retval = 0;
        register char *cp;
        register int exponent;
        register int mantissa;

        cp = *strptr;

        while (isdigit(*cp))
                mval = mval * 10 + (*cp++ - '0');

        if (*cp == '.') {               /* centimeters */
                cp++;
                if (isdigit(*cp)) {
                        cmval = (*cp++ - '0') * 10;
                        if (isdigit(*cp)) {
                                cmval += (*cp++ - '0');
                        }
                }
        }
        cmval = (mval * 100) + cmval;

        for (exponent = 0; exponent < 9; exponent++)
                if (cmval < poweroften[exponent+1])
                        break;

        mantissa = cmval / poweroften[exponent];
        if (mantissa > 9)
                mantissa = 9;

        retval = (mantissa << 4) | exponent;

        *strptr = cp;

        return (retval);
}

/* converts ascii lat/lon to unsigned encoded 32-bit number.
 *  moves pointer. */
static u_int32_t
latlon2ul(latlonstrptr,which)
        char **latlonstrptr;
        int *which;
{
        register char *cp;
        u_int32_t retval;
        int deg = 0, min = 0, secs = 0, secsfrac = 0;

        cp = *latlonstrptr;

        while (isdigit(*cp))
                deg = deg * 10 + (*cp++ - '0');

        while (isspace(*cp))
                cp++;

        if (!(isdigit(*cp)))
                goto fndhemi;

        while (isdigit(*cp))
                min = min * 10 + (*cp++ - '0');
        while (isspace(*cp))
                cp++;

        if (!(isdigit(*cp)))
                goto fndhemi;

        while (isdigit(*cp))
                secs = secs * 10 + (*cp++ - '0');

        if (*cp == '.') {               /* decimal seconds */
                cp++;
                if (isdigit(*cp)) {
                        secsfrac = (*cp++ - '0') * 100;
                        if (isdigit(*cp)) {
                                secsfrac += (*cp++ - '0') * 10;
                                if (isdigit(*cp)) {
                                        secsfrac += (*cp++ - '0');
                                }
                        }
                }
        }

        while (!isspace(*cp))   /* if any trailing garbage */
                cp++;

        while (isspace(*cp))
                cp++;

 fndhemi:
        switch (*cp) {
        case 'N': case 'n':
        case 'E': case 'e':
                retval = ((unsigned)1<<31)
                        + (((((deg * 60) + min) * 60) + secs) * 1000)
                        + secsfrac;
                break;
        case 'S': case 's':
        case 'W': case 'w':
                retval = ((unsigned)1<<31)
                        - (((((deg * 60) + min) * 60) + secs) * 1000)
                        - secsfrac;
                break;
        default:
                retval = 0;     /* invalid value -- indicates error */
                break;
        }

        switch (*cp) {

        case 'N': case 'n':
        case 'S': case 's':
                *which = 1;     /* latitude */
                break;
        case 'E': case 'e':
        case 'W': case 'w':
                *which = 2;     /* longitude */
                break;
        default:
                *which = 0;     /* error */
                break;
        }

        cp++;                   /* skip the hemisphere */

        while (!isspace(*cp))   /* if any trailing garbage */
                cp++;

        while (isspace(*cp))    /* move to next field */
                cp++;

        *latlonstrptr = cp;

        return (retval);
}

/* converts a zone file representation in a string to an RDATA
 * on-the-wire representation. */
u_int32_t
loc_aton(ascii, binary)
        const char *ascii;
        u_char *binary;
{
        const char *cp, *maxcp;
        u_char *bcp;

        u_int32_t latit = 0, longit = 0, alt = 0;
        u_int32_t lltemp1 = 0, lltemp2 = 0;
        int altmeters = 0, altfrac = 0, altsign = 1;
        u_int8_t hp = 0x16;    /* default = 1e6 cm = 10000.00m = 10km */
        u_int8_t vp = 0x13;    /* default = 1e3 cm = 10.00m */
        u_int8_t siz = 0x12;   /* default = 1e2 cm = 1.00m */
        int which1 = 0, which2 = 0;

        cp = ascii;
        maxcp = cp + strlen(ascii);

        lltemp1 = latlon2ul(&cp, &which1);


        lltemp2 = latlon2ul(&cp, &which2);

        switch (which1 + which2) {
        case 3:                 /* 1 + 2, the only valid combination */
                if ((which1 == 1) && (which2 == 2)) { /* normal case */
                        latit = lltemp1;
                        longit = lltemp2;
                } else if ((which1 == 2) && (which2 == 1)) {/*reversed*/
                        longit = lltemp1;
                        latit = lltemp2;
                } else {        /* some kind of brokenness */
                        return 0;
                }
                break;
        default:                /* we didn't get one of each */
                return 0;
        }

        /* altitude */
        if (*cp == '-') {
                altsign = -1;
                cp++;
        }

        if (*cp == '+')
                cp++;

        while (isdigit(*cp))
                altmeters = altmeters * 10 + (*cp++ - '0');

        if (*cp == '.') {               /* decimal meters */
                cp++;
                if (isdigit(*cp)) {
                        altfrac = (*cp++ - '0') * 10;
                        if (isdigit(*cp)) {
                                altfrac += (*cp++ - '0');
                        }
                }
        }

        alt = (10000000 + (altsign * (altmeters * 100 + altfrac)));

        while (!isspace(*cp) && (cp < maxcp))
                                           /* if trailing garbage or m */
                cp++;

        while (isspace(*cp) && (cp < maxcp))
                cp++;

        if (cp >= maxcp)
                goto defaults;

        siz = precsize_aton(&cp);

        while (!isspace(*cp) && (cp < maxcp))/*if trailing garbage or m*/
                cp++;

        while (isspace(*cp) && (cp < maxcp))
                cp++;

        if (cp >= maxcp)
                goto defaults;

        hp = precsize_aton(&cp);

        while (!isspace(*cp) && (cp < maxcp))/*if trailing garbage or m*/
                cp++;

        while (isspace(*cp) && (cp < maxcp))
                cp++;

        if (cp >= maxcp)
                goto defaults;

        vp = precsize_aton(&cp);

 defaults:

        bcp = binary;
        *bcp++ = (u_int8_t) 0;  /* version byte */
        *bcp++ = siz;
        *bcp++ = hp;
        *bcp++ = vp;

	*((u_int32_t *)bcp) = htonl(latit);
	bcp +=  sizeof(u_int32_t);
	*((u_int32_t *)bcp) = htonl(longit);
	bcp +=  sizeof(u_int32_t);
	*((u_int32_t *)bcp) = htonl(alt);
	bcp +=  sizeof(u_int32_t);

        return (16);            /* size of RR in octets */
}

/* takes an on-the-wire LOC RR and prints it in zone file
 * (human readable) format. */

char *
loc_ntoa(binary,ascii)
        const u_char *binary;
        char *ascii;
{

        static char tmpbuf[255*3];

        register char *cp;
        register const u_char *rcp;

        int latdeg, latmin, latsec, latsecfrac;
        int longdeg, longmin, longsec, longsecfrac;
        char northsouth, eastwest;
        int altmeters, altfrac, altsign;

        const int referencealt = 100000 * 100;

        int32_t latval, longval, altval;
        u_int32_t templ;
        u_int8_t sizeval, hpval, vpval, versionval;

        char *sizestr, *hpstr, *vpstr;

        rcp = binary;
        if (ascii)
                cp = ascii;
        else {
                cp = tmpbuf;
        }

        versionval = *rcp++;

        if (versionval) {
                sprintf(cp,"; error: unknown LOC RR version");
                return (cp);
        }

        sizeval = *rcp++;

        hpval = *rcp++;
        vpval = *rcp++;

        latval = (ntohl(*((u_int32_t *)rcp)) - ((unsigned)1<<31));
	rcp += sizeof(u_int32_t);

        longval = (ntohl(*((u_int32_t *)rcp)) - ((unsigned)1<<31));
	rcp += sizeof(u_int32_t);

	templ = ntohl(*((u_int32_t *)rcp));
	rcp += sizeof(u_int32_t);

        if (templ < referencealt) { /* below WGS 84 spheroid */
                altval = referencealt - templ;
                altsign = -1;
        } else {

                altval = templ - referencealt;
                altsign = 1;
        }

        if (latval < 0) {
                northsouth = 'S';
                latval = -latval;
        }
        else
                northsouth = 'N';

        latsecfrac = latval % 1000;
        latval = latval / 1000;
        latsec = latval % 60;
        latval = latval / 60;
        latmin = latval % 60;
        latval = latval / 60;
        latdeg = latval;

        if (longval < 0) {
                eastwest = 'W';
                longval = -longval;
        }
        else
                eastwest = 'E';

        longsecfrac = longval % 1000;
        longval = longval / 1000;
        longsec = longval % 60;
        longval = longval / 60;
        longmin = longval % 60;
        longval = longval / 60;
        longdeg = longval;

        altfrac = altval % 100;
        altmeters = (altval / 100) * altsign;

        sizestr = strdup(precsize_ntoa(sizeval));
        hpstr = strdup(precsize_ntoa(hpval));
        vpstr = strdup(precsize_ntoa(vpval));

        sprintf(cp,
                "%d %.2d %.2d.%.3d %c %d %.2d %.2d.%.3d %c %d.%.2dm
                %sm %sm %sm",
                latdeg, latmin, latsec, latsecfrac, northsouth,
                longdeg, longmin, longsec, longsecfrac, eastwest,
                altmeters, altfrac, sizestr, hpstr, vpstr);

        free(sizestr);
        free(hpstr);
        free(vpstr);

        return (cp);
}
