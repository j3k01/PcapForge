"""SPAN / sensor artefacts: what the capture holds compared with the wire."""

from collections import Counter
from types import SimpleNamespace

from pcapforge.compose.span import Span
from pcapforge.plan import Action
from pcapforge.rng import Rng

ANSWER_ACTION = 7


def wire(count=4000):
    """(time, index, frame, packet) as compose() hands them over; every 10th frame belongs to an
    action the answer key refers to, every 7th is a segment of a multi-segment message."""
    frames = []
    for index in range(count):
        packet = None
        if index % 3:
            packet = SimpleNamespace(action=SimpleNamespace(id=ANSWER_ACTION if index % 10 == 0 else 1),
                                     train=index % 7 == 0)
        data = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + index.to_bytes(4, "big") + bytes(42)
        frames.append((1_700_000_000 + index * 1e-3, index, data, packet))
    return frames


def span(**impairments):
    answer = Action(t=0.0, actor="change", host="rogue", op="write", args={}, id=ANSWER_ACTION)
    plan = SimpleNamespace(impairments=impairments, events=[], facts={"change": {"writes": [{"request": answer}]}})
    return Span(plan, Rng("test", "span"))


def test_drops_and_duplicates_spare_answer_frames_and_message_segments():
    frames = wire()
    out = span(span_duplicates=0.05, sensor_drop=0.02).apply(frames)
    assert out == span(span_duplicates=0.05, sensor_drop=0.02).apply(wire())  # deterministic
    seen = Counter(data for _, _, data, _ in out)
    by_data = {data: (t, p) for t, _, data, p in frames}
    kept = [f for f in frames if f[3] is not None and (f[3].action.id == ANSWER_ACTION or f[3].train)]
    assert all(seen[data] == 1 for _, _, data, _ in kept)
    dropped = [data for data in by_data if data not in seen]
    copied = [data for data, n in seen.items() if n == 2]
    assert 40 <= len(dropped) <= 120 and 120 <= len(copied) <= 280
    assert max(seen.values()) == 2
    # A copy is the identical frame a few microseconds later; the answer key keeps the original.
    times = [t for t, *_ in out]
    assert times == sorted(times)
    for data in copied:
        first, second = [(t, p) for t, _, d, p in out if d == data]
        assert 1e-6 < second[0] - first[0] < 20e-6
        assert first[1] is by_data[data][1] and second[1] is None


def test_vlan_tag_follows_the_mac_addresses_on_every_frame():
    frames = wire(200)
    out = span(vlan=300).apply(frames)
    assert len(out) == len(frames)
    for (_, _, before, _), (_, _, after, _) in zip(frames, out):
        assert after == before[:12] + b"\x81\x00\x01\x2c" + before[12:]


def test_no_impairments_leave_the_frames_untouched():
    frames = wire(100)
    assert span(retransmit_rate=0.001, mid_session=True).apply(frames) is frames
