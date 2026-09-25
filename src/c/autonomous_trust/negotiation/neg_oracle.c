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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "negotiation/neg_oracle.h"

/* Filled by constructors before main(), then read-only, so unlocked -- as
 * processes/extension.c. Arms kept sorted by order. */
static const neg_oracle_arm_t *arms[NEG_ORACLE_ARM_MAX];
static size_t n_arms = 0;
static const neg_oracle_t *oracles[NEG_ORACLE_MAX];
static size_t n_oracles = 0;
static const char *(*quantity_fn)(const char *) = NULL;
static double (*competence_fn)(const char *, const char *) = NULL;

int neg_oracle_register(const neg_oracle_t *oracle)
{
    if (oracle == NULL || oracle->name == NULL || oracle->name[0] == '\0') {
        fprintf(stderr, "neg_oracle_register: refusing an unnamed oracle\n");
        return -1;
    }
    if (neg_oracle_present(oracle->name)) {
        fprintf(stderr, "neg_oracle_register: refusing %s: already declared\n",
                oracle->name);
        return -1;
    }
    if (n_oracles >= NEG_ORACLE_MAX) {
        fprintf(stderr, "neg_oracle_register: refusing %s: registry full\n",
                oracle->name);
        return -1;
    }
    oracles[n_oracles++] = oracle;
    return 0;
}

bool neg_oracle_present(const char *name)
{
    if (name == NULL)
        return false;
    for (size_t i = 0; i < n_oracles; i++)
        if (strcmp(oracles[i]->name, name) == 0)
            return true;
    return false;
}

int neg_oracle_arm_register(const neg_oracle_arm_t *arm)
{
    if (arm == NULL || arm->name == NULL || arm->name[0] == '\0') {
        fprintf(stderr, "neg_oracle_arm_register: refusing an unnamed arm\n");
        return -1;
    }
    if ((arm->score == NULL) == (arm->observe == NULL)) {
        fprintf(stderr, "neg_oracle_arm_register: refusing %s: needs exactly one"
                        " of score / observe\n", arm->name);
        return -1;
    }
    if (n_arms >= NEG_ORACLE_ARM_MAX) {
        fprintf(stderr, "neg_oracle_arm_register: refusing %s: registry full\n",
                arm->name);
        return -1;
    }
    size_t at = n_arms;
    while (at > 0 && arms[at - 1]->order > arm->order) {
        arms[at] = arms[at - 1];
        at--;
    }
    arms[at] = arm;
    n_arms++;
    return 0;
}

bool neg_oracles_score(const neg_score_input_t *in, double *score, const char **channel)
{
    for (size_t i = 0; i < n_arms; i++) {
        if (arms[i]->observe != NULL) {
            arms[i]->observe(in);
            continue;
        }
        if (arms[i]->score(in, score, channel))
            return true;
    }
    return false;
}

int neg_oracle_provide_quantity(const char *(*fn)(const char *capability))
{
    if (fn == NULL || quantity_fn != NULL) {
        fprintf(stderr, "neg_oracle_provide_quantity: refusing a %s provider\n",
                fn == NULL ? "NULL" : "second");
        return -1;
    }
    quantity_fn = fn;
    return 0;
}

const char *neg_oracle_reported_quantity(const char *capability)
{
    if (quantity_fn == NULL || capability == NULL || capability[0] == '\0')
        return NULL;
    return quantity_fn(capability);
}

int neg_oracle_provide_competence(double (*fn)(const char *cap, const char *subject))
{
    if (fn == NULL || competence_fn != NULL) {
        fprintf(stderr, "neg_oracle_provide_competence: refusing a %s provider\n",
                fn == NULL ? "NULL" : "second");
        return -1;
    }
    competence_fn = fn;
    return 0;
}

double neg_oracle_competence(const char *cap, const char *subject)
{
    if (competence_fn == NULL)
        return NEG_NEUTRAL_COMPETENCE;
    return competence_fn(cap, subject);
}

/* The declarations a node's environment can make, and the library that must
 * be present to honour each. Names only: the core knows what a layer is
 * called, never what it does. */
static const struct { const char *env; const char *oracle; } declarations[] = {
    { "AT_PHYSICS",      "physics" },
    { "AT_CALIBRATION",  "calibration" },
    { "AT_PREQUENTIAL",  "prequential" },
    { "AT_CERTIFICATES", "certificates" },
};

int neg_oracles_check_env(logger_t *logger)
{
    int rc = 0;
    for (size_t i = 0; i < sizeof(declarations) / sizeof(declarations[0]); i++) {
        const char *v = getenv(declarations[i].env);
        if (v == NULL || v[0] == '\0' || neg_oracle_present(declarations[i].oracle))
            continue;
        log_error(logger, "Negotiation: $%s is set, but libat_%s is not loaded;"
                          " refusing to start rather than skip the check it"
                          " declares\n",
                  declarations[i].env, declarations[i].oracle);
        rc = -1;
    }
    return rc;
}

void neg_oracles_reset(void)
{
    for (size_t i = 0; i < n_oracles; i++)
        if (oracles[i]->reset != NULL)
            oracles[i]->reset();
}
