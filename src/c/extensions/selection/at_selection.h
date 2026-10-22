/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *******************/

#ifndef AT_SELECTION_LINK_H
#define AT_SELECTION_LINK_H

/**
 * @file at_selection.h
 * @brief Selective assignment (R+D.md §12.7; libat_selection).
 *
 * Linking libat_selection registers, through negotiation/neg_oracle.h, its
 * declaration, and through negotiation/neg_ext.h the selection hook and the
 * two audit verbs (selection_live.c, RD_12.7_SELECTIVE_ASSIGNMENT_PLAN.md).
 * It links libat_certificates (SplitMix64). It speaks only when
 * $AT_SELECTION names a declaration, so linking or loading it changes
 * nothing on its own; a node that declares the layer without it refuses to
 * start (neg_oracles_check_env).
 *
 * A static link keeps the registration only if something references the
 * object, so a program that links at_selection_static without
 * --whole-archive calls at_selection_link() once.
 *
 * See doc/architecture/selection.md.
 */

#include <jansson.h>

#include "processes/processes.h"

/** The audit verbs: "draw n: was I eligible, and how did the coin fall for
 *  me?" and its answer. Both are answered only when verified. */
#define AT_SEL_AUDIT_QUERY "selection audit"
#define AT_SEL_AUDIT_REPLY "selection audit reply"

/** Keeps the layer's registration constructors in a static link. */
void at_selection_link(void);


/** Conformance and tests: use @p model (an at_selection_model_t), a chain
 *  seeded from @p root (32 bytes) and files in @p cfg_dir for @p proc,
 *  instead of $AT_SELECTION, fresh entropy and the configuration
 *  directory. @return 0, -1 when the process table is full. */
int at_selection_configure(const process_t *proc, const void *model,
                           const unsigned char *root, const char *cfg_dir);

/** How many findings @p proc's audit recorded, for @p requestor (NULL for
 *  any) and @p reason (NULL for any). */
long at_selection_finding_count(const process_t *proc, const char *requestor,
                                const char *reason);

/** @p proc's decision log as Python's records (new reference). */
json_t *at_selection_log_json(const process_t *proc);

#endif /* AT_SELECTION_LINK_H */
