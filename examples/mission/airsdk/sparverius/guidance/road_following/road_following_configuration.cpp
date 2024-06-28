/**
 * Copyright (c) 2023 Parrot Drones SAS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of the Parrot Company nor the names
 *   of its contributors may be used to endorse or promote products
 *   derived from this software without specific prior written
 *   permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * PARROT COMPANY BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define ULOG_TAG gdnc_absolute_move_cfg
#include <ulog.hpp>
ULOG_DECLARE_TAG(ULOG_TAG);

#include "road_following_configuration.hpp"

#include <cfgreader/cfgreader.hpp>

#define CFG_CHECK(E) ULOG_ERRNO_RETURN_ERR_IF(E < 0, EINVAL)

int RoadFollowingConfiguration::read(const std::string &path)
{
	return cfgreader::loadFromFile(*this, path, "road_following");
}

namespace cfgreader {
template <>
int SettingReader<RoadFollowingConfiguration>::read(
	const libconfig::Setting &set,
	T &v)
{
	using CR = ConfigReader;

	CFG_CHECK(CR::getField(set, "tickPeriod", v.tickPeriod));
	CFG_CHECK(CR::getField(
		set, "cameraPitchPosition", v.cameraPitchPosition));
	CFG_CHECK(CR::getField(set,
			       "missingTelemetryValuesLimit",
			       v.missingTelemetryValuesLimit));
	return 0;
}
} // namespace cfgreader
