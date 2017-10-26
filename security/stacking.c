/*
 *  Maintain a mapping between the secid used in networking
 *  and the set of secids used by the security modules.
 *
 *  Author:
 *	Casey Schaufler <casey@schaufler-ca.com>
 *
 *  Copyright (C) 2017 Casey Schaufler <casey@schaufler-ca.com>
 *  Copyright (C) 2017 Intel Corporation.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2,
 *      as published by the Free Software Foundation.
 */

#include <linux/lsm_hooks.h>

struct token_entry {
	int			used;	/* relative age of the entry */
	u32			token;	/* token value */
	struct lsm_secids	secids;	/* secids mapped to this token */
};

/*
 * Add an entry to the table when asked for a mapping that
 * isn't already present. If the table is full throw away the
 * least recently used entry. If the entry is present undate
 * when it was used.
 */
#define TOKEN_AGE_LIMIT (MAX_INT >> 2)
#define TOKEN_LIMIT 0x20000000
#define TOKEN_SET_SIZE 200
#define TOKEN_BIT 0x80000000
int token_used;
u32 token_next;
struct lsm_secids null_secids;
struct token_entry token_set[TOKEN_SET_SIZE];

#ifdef CONFIG_SECURITY_LSM_DEBUG
static void report_token(const char *msg, const struct token_entry *te)
{
	int i;

	pr_info("LSM: %s token=%08x %u,%u,%u,%u,%u,%u,%u,%u\n", msg, te->token,
		te->secids.secid[0], te->secids.secid[1], te->secids.secid[2],
		te->secids.secid[3], te->secids.secid[4], te->secids.secid[5],
		te->secids.secid[6], te->secids.secid[7]);
	for (i = 0; i < LSM_MAX_MAJOR; i++)
		if (te->secids.secid[i] & TOKEN_BIT)
			pr_info("LSM: module %d provided a token.\n", i);
}
#else
static inline void report_token(const char *msg, const struct token_entry *te)
{
}
#endif

static int next_used(void)
{
	if (token_next >= TOKEN_LIMIT) {
		pr_info("LSM: Security token use overflow - safe reset\n");
		token_used = 0;
	}
	return ++token_used;
}

static u32 next_token(void)
{
	if (token_next >= TOKEN_LIMIT) {
		pr_info("LSM: Security token overflow - safe reset\n");
		token_next = 0;
	}
	return ++token_next | TOKEN_BIT;
}

u32 lsm_secids_to_token(const struct lsm_secids *secids)
{
	int i;
	int j;
	int old;

#ifdef CONFIG_SECURITY_LSM_DEBUG
	for (i = 0; i < LSM_MAX_MAJOR; i++)
		if (secids->secid[i] & TOKEN_BIT)
			pr_info("LSM: %s secid[%d]=%08x has token bit\n",
				__func__, i, secids->secid[i]);
#endif

	/*
	 * If none of the secids are set whoever sent this here
	 * was thinking "0".
	 */
	if (!memcmp(secids, &null_secids, sizeof(*secids)))
		return 0;

	for (i = 0; i < TOKEN_SET_SIZE; i++) {
		if (token_set[i].token == 0)
			break;
		if (!memcmp(secids, &token_set[i].secids, sizeof(*secids))) {
			token_set[i].used = next_used();
			return token_set[i].token;
		}
	}
	if (i == TOKEN_SET_SIZE) {
		old = token_used;
		for (j = 0; j < TOKEN_SET_SIZE; j++) {
			if (token_set[j].used < old) {
				old = token_set[j].used;
				i = j;
			}
		}
	}
	token_set[i].secids = *secids;
	token_set[i].token = next_token();
	token_set[i].used = next_used();

	report_token("new", &token_set[i]);

	return token_set[i].token;
}

void lsm_token_to_secids(const u32 token, struct lsm_secids *secids)
{
	int i;
	struct lsm_secids fudge;

	if (token) {
		if (!(token & TOKEN_BIT)) {
#ifdef CONFIG_SECURITY_LSM_DEBUG
			pr_info("LSM: %s token=%08x has no token bit\n",
				__func__, token);
#endif
			for (i = 0; i < LSM_MAX_MAJOR; i++)
				fudge.secid[i] = token;
			*secids = fudge;
			return;
		}
		for (i = 0; i < TOKEN_SET_SIZE; i++) {
			if (token_set[i].token == 0)
				break;
			if (token_set[i].token == token) {
				*secids = token_set[i].secids;
				token_set[i].used = next_used();
				return;
			}
		}
#ifdef CONFIG_SECURITY_LSM_DEBUG
	pr_info("LSM: %s token=%u was not found\n", __func__, token);
#endif
	}
	*secids = null_secids;
}

u32 lsm_token_get_secid(const u32 token, int lsm)
{
	struct lsm_secids secids;

        lsm_token_to_secids(token, &secids);
	return secids.secid[lsm];
}

u32 lsm_token_set_secid(const u32 token, u32 lsecid, int lsm)
{
	struct lsm_secids secids;

#ifdef CONFIG_SECURITY_LSM_DEBUG
	if (!(token & TOKEN_BIT)) {
		if (token)
			pr_info("LSM: %s token=%08x has no token bit\n",
				__func__, token);
#else
	if (!token) {
#endif
		lsm_secids_init(&secids);
	} else {
		lsm_token_to_secids(token, &secids);
		if (secids.secid[lsm] == lsecid)
			return token;
	}

	secids.secid[lsm] = lsecid;
	return lsm_secids_to_token(&secids);
}

void lsm_secids_init(struct lsm_secids *secids)
{
	*secids = null_secids;
}
