/*
**  Copyright (c) 2004, 2005 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

/* system includes */
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

/* libmarid includes */
#include "sm-maridp.h"

#ifndef lint
static char sm_marid_unused
sm_marid_ip_c_id[] = "@(#)$Id: sm-marid-ip.c,v 1.6 2005/12/08 21:52:32 msk Exp $";
#endif /* !lint */

/*
**  SM_MARID_IP_VERSION -- is this ipv4 or ipv6?  
**
**	Parameters:
**		ip_s -- in: the textual IP address
**		ip_e -- in: end of the textual IP address
**
**	Returns:
**		0 if this isn't an IP address,
**		'4' if it's IPV4, '6' if it's IPV6.
*/

int
sm_marid_ip_version(char const *ip_s, char const *ip_e)
{
	size_t		ndots;
	char const	*p;
	if (ip_s == NULL || ip_e == NULL || ip_s == ip_e)
		return 0;

	for (ndots = 0, p = ip_s; p < ip_e; p++)
		if (*p == '.')
			ndots++;
		else if (isascii((unsigned char)*p) && !isdigit(*p))
			return '6';

	if (ndots <= 3)
		return '4';
	return '6';
}

#define ishexdigit(c) (isascii(c) && (isdigit(c) || (c >= 'A' && c <= 'F') \
				      || (c >= 'a' && c <= 'f')))

/*
**  SM_MARID_IP_CANON -- transform a written IP address into a byte string
**
**	Parameters:
**		ip_s -- in: the textual IP address
**		ip_e -- in: end of the textual IP address
**		bytes_out -- out: store bytes here.
**		n_out -- in: how much space we have; out: occupied space.
**
**	Returns:
**		0 on success, an error on syntax error.
*/

int
sm_marid_ip_canon(
	char const	*ip_s,
	char const	*ip_e,
	unsigned char	*bytes_out,
	size_t		*n_out)
{
	size_t		n;
	size_t		ndots;
	int		ncolon;
	int		splitpos = -1;
	char const	*p;
	
	if (ip_s == NULL || ip_e == NULL || ip_s == ip_e || *n_out < 4)
	{
	    *n_out = 0;
	    return -1;
	}

	n = *n_out;
	*n_out = 0;

	memset(bytes_out, 0, n);

	ncolon = ndots = 0;
	for (p = ip_s; p < ip_e; p++)
	{
		if (*p == '.')
		    ndots++;
		if (*p == ':')
		    ncolon++;
	}

	unsigned long	val;
	p = ip_s;

	if (ncolon > 0)
	{
	    if (n < 16)
		// ipv6 address but not enough space to store it...  SCREAM!
		return -1;

	    if (ncolon > 1 && *p == ':' && p[1] == ':')
	    {
		splitpos = 0;
		p += 2;
		ncolon -= 2;
	    }

	    while (p < ip_e && *n_out < n)
	    {
		val = 0;

		if (!ishexdigit(*p))
		    return -1;

		do
		{
		    val *= 16;
		    if (isdigit(*p))
			val += *p - '0';
		    else if (islower(*p))
			val += *p - 'a' + 10;
		    else
			val += *p - 'A' + 10;
		    p++;
		} while (ishexdigit(*p) && p < ip_e);

		if (*p == '.')
		{
		    // back up and switch to ipv4 logic
		    while (--p > ip_s && ishexdigit(*p))
			;
		    ++p;
		    break;
		}

		bytes_out[ (*n_out)++ ] = val >> 8;
		bytes_out[ (*n_out)++ ] = val & 0xff;

		if (p >= ip_e)
		    break;

		if (*p != ':')
		    return -1;

		if (*++p == ':')
		{
		    if (splitpos >= 0)
			return -1;	// multiple ::
		    --ncolon;
		    ++p;
		    splitpos = *n_out;
		}

		if (--ncolon <= 0 && ndots > 0)
		    break;
	    }
	}

	if (ndots <= 3 && p < ip_e)
	{
		int cnt = 4;
		while (*n_out < n)
		{
			val = 0;
			if (!isascii(*p) || !isdigit(*p))
				return -1;

			while (isascii(*p) && isdigit(*p) && p < ip_e)
			{
				val *= 10;
				val += *p - '0';
				p++;
			}
			if (p >= ip_e)
				break;

			if (*p != '.')
				return -1;
			p++;

			--cnt;
			bytes_out[ (*n_out)++ ] = val;
		}

		if (cnt + *n_out > n)
			cnt = n - *n_out;

		switch (cnt)
		{
		  case 4:
			bytes_out[(*n_out)++] = 0xFF & (val >> 24);
		  case 3:
			bytes_out[(*n_out)++] = 0xFF & (val >> 16);
		  case 2:
			bytes_out[(*n_out)++] = 0xFF & (val >> 8);
		  case 1:
			bytes_out[(*n_out)++] = 0xFF & val;
		}
	}

	if (splitpos >= 0 && *n_out < 16 && n >= 16)
	{
	    int d = *n_out;
	    int l = 16;

	    while (d > splitpos)
		bytes_out[--l] = bytes_out[--d];
	    while (l > splitpos)
		bytes_out[--l] = 0;
	    *n_out = 16;
	}

	return 0;
}

/*
**  SM_MARID_IP_EQ -- compare top bits of two ip addresses for equality
**
**	Parameters:
**		a -- bytes of the first address
**		b -- bytes of the second address
**		n -- # of bytes in both
**		bits -- # of bits to compare
**
**	Returns:
**		1 if they match, 0 if they don't.
*/

int
sm_marid_ip_eq(
	unsigned char const	*a,
	unsigned char const	*b,
	size_t			n,
	size_t			bits)
{
	size_t			i = 0;

	if (a == NULL && b == NULL)
		return 1;
	if (a == NULL || b == NULL)
		return 0;

	while (bits >= CHAR_BIT && i < n)
	{
		if (*a++ != *b++)
			return 0;
		i++;
		bits -= CHAR_BIT;
	}

	if (bits == 0 || i >= n)
		return 1;

	return  ((*a ^ *b) >> (CHAR_BIT - bits)) == 0;
}

#ifdef TEST
typedef unsigned char ipa[16];

int
main(int ac, char **av)
{
    ipa	a1, a2;
    size_t s1, s2;

    if (ac < 3)
	return 2;

    s1 = sizeof a1;
    s2 = sizeof a2;

    if (sm_marid_ip_canon(av[1], av[1]+strlen(av[1]), a1, &s1))
	return 2;

    if (sm_marid_ip_canon(av[2], av[2]+strlen(av[2]), a2, &s2))
	return 2;

    if (sm_marid_ip_eq(a1, a2, s1, s1 * CHAR_BIT))
	return 1;

    fputs("diff\n", stdout);

    return 0;
}
#endif
