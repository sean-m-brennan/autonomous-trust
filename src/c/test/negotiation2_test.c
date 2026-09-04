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

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <time.h>
#include <uuid/uuid.h>

#include <stdint.h>
#include <stdio.h>

#include "negotiation/task_priv.h"
#include "negotiation/negotiation.h"
#include "negotiation/neg_proc_priv.h"
#include "bootstrap/bootstrap_capabilities.h"
#include "reputation/tx_channel.h"

DEFINE_TEST(test_job_queue_create_destroy)
{
    job_queue_t *q = NULL;
    ck_assert_ret_ok(job_queue_create(&q));
    ck_assert_ptr_nonnull(q);
    ck_assert_int_eq(job_queue_count(q), 0);

    job_t job;
    memset(&job, 0, sizeof(job));
    uuid_generate(job.task.uuid);
    job.start_time = time(NULL);
    job.end_time = job.start_time + 60;
    ck_assert_ret_ok(job_queue_push(q, &job));
    ck_assert_int_eq(job_queue_count(q), 1);

    job_queue_destroy(q);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_job_queue_min)
{
    job_queue_t q;
    ck_assert_ret_ok(job_queue_init(&q));

    /* Min on empty queue should fail */
    job_t out;
    ck_assert_ret_nonzero(job_queue_min(&q, &out));

    /* Add two jobs with different start times */
    job_t job1, job2;
    memset(&job1, 0, sizeof(job1));
    memset(&job2, 0, sizeof(job2));
    uuid_generate(job1.task.uuid);
    uuid_generate(job2.task.uuid);
    job1.start_time = time(NULL) + 100;
    job1.end_time = job1.start_time + 60;
    job2.start_time = time(NULL) + 200;
    job2.end_time = job2.start_time + 60;

    ck_assert_ret_ok(job_queue_push(&q, &job1));
    ck_assert_ret_ok(job_queue_push(&q, &job2));

    /* Min should return first job */
    ck_assert_ret_ok(job_queue_min(&q, &out));
    ck_assert(uuid_compare(out.task.uuid, job1.task.uuid) == 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_job_queue_contains)
{
    job_queue_t q;
    ck_assert_ret_ok(job_queue_init(&q));

    job_t job;
    memset(&job, 0, sizeof(job));
    uuid_generate(job.task.uuid);
    job.start_time = time(NULL);
    job.end_time = job.start_time + 60;

    uuid_t other_uuid;
    uuid_generate(other_uuid);

    ck_assert(job_queue_contains(&q, job.task.uuid) == false);
    ck_assert_ret_ok(job_queue_push(&q, &job));
    ck_assert(job_queue_contains(&q, job.task.uuid) == true);
    ck_assert(job_queue_contains(&q, other_uuid) == false);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_job_queue_clear)
{
    job_queue_t q;
    ck_assert_ret_ok(job_queue_init(&q));

    for (int i = 0; i < 5; i++) {
        job_t job;
        memset(&job, 0, sizeof(job));
        uuid_generate(job.task.uuid);
        job.start_time = time(NULL) + i * 60;
        job.end_time = job.start_time + 30;
        ck_assert_ret_ok(job_queue_push(&q, &job));
    }
    ck_assert_int_eq(job_queue_count(&q), 5);

    job_queue_clear(&q);
    ck_assert_int_eq(job_queue_count(&q), 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_job_queue_find_nearest_slot)
{
    job_queue_t q;
    ck_assert_ret_ok(job_queue_init(&q));

    /* Empty queue: slot should be now */
    time_t slot = 0;
    ck_assert_ret_ok(job_queue_find_nearest_slot(&q, 30, 1, &slot));
    ck_assert(slot > 0);

    /* Add a job and find a slot */
    job_t job;
    memset(&job, 0, sizeof(job));
    uuid_generate(job.task.uuid);
    job.start_time = time(NULL) + 10;
    job.end_time = job.start_time + 60;
    ck_assert_ret_ok(job_queue_push(&q, &job));

    ck_assert_ret_ok(job_queue_find_nearest_slot(&q, 30, 2, &slot));
    ck_assert(slot > 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_task_tracker_create_destroy)
{
    uuid_t task_uuid;
    uuid_generate(task_uuid);

    task_tracker_t *tracker = NULL;
    ck_assert_ret_ok(task_tracker_create(&tracker, task_uuid, 3));
    ck_assert_ptr_nonnull(tracker);
    ck_assert_int_eq(task_tracker_result_count(tracker), 0);

    uuid_t peer;
    uuid_generate(peer);
    const uint8_t data[] = {0xAB, 0xCD};
    ck_assert_ret_ok(task_tracker_set_result(tracker, peer, data, sizeof(data)));
    ck_assert_int_eq(task_tracker_result_count(tracker), 1);

    task_tracker_destroy(tracker);
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------
 * Requestor-side result scoring (R+D.md §12.7 / §12.8)
 *
 * The requestor keeps what it asked for on the tracker, and judges the
 * returned answer against THAT. Both halves are pinned here: the retention,
 * and the scoring rules the retained record feeds.
 * ------------------------------------------------------------------ */

DEFINE_TEST(test_task_tracker_retains_the_request)
{
    uuid_t task_uuid;
    uuid_generate(task_uuid);
    task_tracker_t tracker;
    memset(&tracker, 0xAB, sizeof(tracker));   /* garbage, deliberately */
    ck_assert_ret_ok(task_tracker_init(&tracker, task_uuid, 1));
    /* init CLEARS the request record: garbage here would be read as a
     * capability name at scoring time. */
    ck_assert_str_eq(tracker.capability_name, "");
    ck_assert_str_eq(tracker.kwargs_json, "");

    ck_assert_ret_ok(task_tracker_set_request(&tracker, "at.handshake",
                                              "{\"nonce\":7}"));
    ck_assert_str_eq(tracker.capability_name, "at.handshake");
    ck_assert_str_eq(tracker.kwargs_json, "{\"nonce\":7}");

    /* NULL clears, so a re-announce with no arguments cannot leave the old
     * challenge standing. */
    ck_assert_ret_ok(task_tracker_set_request(&tracker, "data_fetch", NULL));
    ck_assert_str_eq(tracker.capability_name, "data_fetch");
    ck_assert_str_eq(tracker.kwargs_json, "");

    task_tracker_free(&tracker);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_score_probe_result_uses_our_own_challenge)
{
    const char *channel = NULL;
    /* Honest answer to the nonce WE sent. */
    double score = negotiation_score_task_result("at.handshake",
                                                 "{\"nonce\":41}", "42", 2,
                                                 NULL, NULL, NULL, 0.0, 0, &channel);
    ck_assert_double_eq_tol(score, 0.9, 1e-9);
    ck_assert_str_eq(channel, TX_CHANNEL_PROBE);

    /* The same reply against a different retained challenge scores as a
     * defection. This is the integrity property the whole design turns on: a
     * peer that computed the wrong answer would report the challenge its
     * answer satisfies, so the expected value has to come from our side. */
    score = negotiation_score_task_result("at.handshake", "{\"nonce\":77}",
                                          "42", 2, NULL, NULL, NULL, 0.0, 0, &channel);
    ck_assert_double_eq_tol(score, 0.1, 1e-9);
    ck_assert_str_eq(channel, TX_CHANNEL_PROBE);

    /* A probe answered with prose is not answered. The reply is parsed as
     * NaN rather than 0, which matters most for at.time-attest below: a
     * finite 0 there is "forgivable drift" (0.5), so reading prose as zero
     * would grade nonsense more kindly than a merely late clock. Python
     * reaches the same 0.1 by float() raising on the same input. */
    score = negotiation_score_task_result("at.handshake", "{\"nonce\":41}",
                                          "forty-two", 9, NULL, NULL, NULL, 0.0, 0, &channel);
    ck_assert_double_eq_tol(score, 0.1, 1e-9);
    ck_assert_str_eq(channel, TX_CHANNEL_PROBE);
    /* Nor is a partly-numeric one: "42abc" is not 42. */
    score = negotiation_score_task_result("at.handshake", "{\"nonce\":41}",
                                          "42abc", 5, NULL, NULL, NULL, 0.0, 0, &channel);
    ck_assert_double_eq_tol(score, 0.1, 1e-9);

    /* at.time-attest: a clock far from ours is forgivable (0.5), because the
     * comparison includes the round trip; an unparseable one is not (0.1). */
    score = negotiation_score_task_result("at.time-attest", "", "0", 1,
                                          NULL, NULL, NULL, 0.0, 0, &channel);
    ck_assert_double_eq_tol(score, 0.5, 1e-9);
    ck_assert_str_eq(channel, TX_CHANNEL_PROBE);
    score = negotiation_score_task_result("at.time-attest", "", "soon", 4,
                                          NULL, NULL, NULL, 0.0, 0, &channel);
    ck_assert_double_eq_tol(score, 0.1, 1e-9);

    /* Echo: byte-equal to the token we sent, or nothing. */
    score = negotiation_score_task_result("at.echo-challenge",
                                          "{\"payload\":\"echo:cafe\"}",
                                          "echo:cafe", 9, NULL, NULL, NULL, 0.0, 0, &channel);
    ck_assert_double_eq_tol(score, 0.9, 1e-9);
    ck_assert_str_eq(channel, TX_CHANNEL_PROBE);
    score = negotiation_score_task_result("at.echo-challenge",
                                          "{\"payload\":\"echo:cafe\"}",
                                          "echo:beef", 9, NULL, NULL, NULL, 0.0, 0, &channel);
    ck_assert_double_eq_tol(score, 0.1, 1e-9);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_score_non_probe_result_is_completion)
{
    const char *channel = NULL;
    /* An ordinary capability: this runtime attaches no ZK proof, so it is
     * always Python's "ZKP unavailable" arm -- score on the fact something
     * came back, and say `task_outcome` so a missing proof infrastructure
     * does not read as a failed proof. */
    double score = negotiation_score_task_result("data_fetch", "", "done", 4,
                                                 NULL, NULL, NULL, 0.0, 0, &channel);
    ck_assert_double_eq_tol(score, 0.8, 1e-9);
    ck_assert_str_eq(channel, TX_CHANNEL_TASK_OUTCOME);

    score = negotiation_score_task_result("data_fetch", "", NULL, 0, NULL, NULL, NULL, 0.0, 0, &channel);
    ck_assert_double_eq_tol(score, 0.3, 1e-9);
    ck_assert_str_eq(channel, TX_CHANNEL_TASK_OUTCOME);

    /* No retained capability name at all (a pre-§12.7 tracker, or a result
     * for a task we have no record of): ordinary completion scoring, never a
     * probe verdict against a challenge we do not have. */
    score = negotiation_score_task_result("", "", "done", 4, NULL, NULL, NULL, 0.0, 0, &channel);
    ck_assert_double_eq_tol(score, 0.8, 1e-9);
    ck_assert_str_eq(channel, TX_CHANNEL_TASK_OUTCOME);
    score = negotiation_score_task_result(NULL, NULL, "done", 4, NULL, NULL, NULL, 0.0, 0, &channel);
    ck_assert_double_eq_tol(score, 0.8, 1e-9);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_score_probe_with_no_retained_challenge)
{
    /* A probe capability whose challenge we did not keep. at.handshake's
     * expected value falls back to 0 + 1, so a peer's "42" scores 0.1 --
     * and it stays on the `probe` channel, because the failure is a probe
     * failure and the operator reading the chain should see that rather than
     * an ordinary bad task grade. */
    const char *channel = NULL;
    double score = negotiation_score_task_result("at.handshake", "", "42", 2,
                                                 NULL, NULL, NULL, 0.0, 0, &channel);
    ck_assert_double_eq_tol(score, 0.1, 1e-9);
    ck_assert_str_eq(channel, TX_CHANNEL_PROBE);

    /* at.time-attest carries no challenge by design, so an absent record
     * costs it nothing: an honest clock still scores 0.9. */
    char now_str[32] = {0};
    snprintf(now_str, sizeof(now_str), "%.3f", at_time_attest());
    score = negotiation_score_task_result("at.time-attest", "", now_str,
                                          strlen(now_str), NULL, NULL, NULL, 0.0, 0, &channel);
    ck_assert_double_eq_tol(score, 0.9, 1e-9);
    ck_assert_str_eq(channel, TX_CHANNEL_PROBE);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_task_kwargs_survive_the_proto_round_trip)
{
    /* The challenge has to reach the responder, and task_t's IPC encoding is
     * protobuf (field 13). A task that loses its arguments in transit means a
     * responder computing the wrong answer and being scored for it. */
    task_t task;
    memset(&task, 0, sizeof(task));
    uuid_generate(task.uuid);
    uuid_generate(task.requestor_uuid);
    strncpy(task.capability.name, "at.echo-challenge", CAP_NAMELEN);
    task.seq = 3;
    snprintf(task.kwargs_json, sizeof(task.kwargs_json),
             "{\"payload\":\"echo:deadbeef\"}");

    void *data = NULL;
    size_t len = 0;
    ck_assert_ret_ok(task_to_proto(&task, sizeof(task), &data, &len));
    ck_assert_ptr_nonnull(data);

    task_t back;
    memset(&back, 0, sizeof(back));
    ck_assert_ret_ok(proto_to_task((uint8_t *)data, len, &back));
    ck_assert_str_eq(back.kwargs_json, "{\"payload\":\"echo:deadbeef\"}");
    ck_assert_str_eq(back.capability.name, "at.echo-challenge");
    ck_assert(back.seq == 3);

    /* An unstamped task (no arguments) round-trips as no arguments, which is
     * what every task predating the field meant. */
    task.kwargs_json[0] = '\0';
    void *data2 = NULL;
    size_t len2 = 0;
    ck_assert_ret_ok(task_to_proto(&task, sizeof(task), &data2, &len2));
    task_t back2;
    memset(&back2, 0, sizeof(back2));
    ck_assert_ret_ok(proto_to_task((uint8_t *)data2, len2, &back2));
    ck_assert_str_eq(back2.kwargs_json, "");
}
END_TEST_DEFINITION()

RUN_TESTS(Negotiation2, test_job_queue_create_destroy, test_job_queue_min,
          test_job_queue_contains, test_job_queue_clear,
          test_job_queue_find_nearest_slot, test_task_tracker_create_destroy,
          test_task_tracker_retains_the_request,
          test_score_probe_result_uses_our_own_challenge,
          test_score_non_probe_result_is_completion,
          test_score_probe_with_no_retained_challenge,
          test_task_kwargs_survive_the_proto_round_trip)
