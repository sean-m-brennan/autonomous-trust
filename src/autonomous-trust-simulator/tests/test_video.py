import os
import threading

import cv2
import imutils
import numpy as np
import pytest

from autonomous_trust.simulator.video import server, client


video_file = 'data/220505_02_MTB_4k_015.mp4'
size = 640


@pytest.fixture
def video_image():
    base_dir = os.path.dirname(server.__file__)
    vid = cv2.VideoCapture(os.path.join(base_dir, video_file))
    _, frame = vid.read()
    frame = imutils.resize(frame, width=size)
    return frame


def mean_squared_error(img1, img2):
    assert img1.shape == img2.shape
    h, w, _ = img1.shape
    diff = cv2.subtract(img1, img2)
    err = np.sum(diff ** 2)
    return err / (float(h * w))


def test_client_frame(video_image):
    host = 'localhost'
    port = 9999
    srv = server.VideoSource()
    cli = client.VideoRcvr()
    t1 = threading.Thread(target=srv.run, args=(video_file,), kwargs={'synchronized': True, 'size': size})
    t2 = threading.Thread(target=cli.reconnect, args=(host, port))
    t1.start()  # must be first
    t2.start()  # must be second
    rcvd_image, _ = cli.get_frame(noisy=False)
    cli.halt = True
    srv.halt = True
    t2.join()
    t1.join()
    mse = mean_squared_error(video_image, rcvd_image)
    assert mse < .00001


