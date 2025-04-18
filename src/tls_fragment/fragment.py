import random
from log import logger


def fragment_content(data: str, num: int) -> list:
    """
    frag <data> into num pieces
    """
    data_lenth = len(data)
    fragmented_content = []
    try:
        dividing_points = random.sample(
            range(1, data_lenth - 1), min(num, data_lenth - 2)
        )
    except:
        fragmented_content.append(data)
        return
    dividing_points.append(0)
    dividing_points.append(data_lenth)
    dividing_points.sort()
    for i in range(0, len(dividing_points) - 1):
        fragmented_content.append(data[dividing_points[i] : dividing_points[i + 1]])
    return fragmented_content


def fragment_pattern(data, pattern, num):
    """
    fragment pattern into at least num parts.
    """
    fragmented_data = []
    position = data.find(pattern)
    logger.debug("%s %s", pattern, position)
    if position == -1:
        fragmented_data.append(data)
        return fragmented_data
    pattern_lenth = len(pattern)
    data_lenth = len(data)

    fragmented_data.append(data[0:position])

    lenth = pattern_lenth // num
    if pattern_lenth % num != 0:
        lenth += 1

    for i in range(0, num):
        fragmented_data.append(
            data[position + i * lenth : position + min((i + 1) * lenth, pattern_lenth)]
        )

    fragmented_data.append(data[position + pattern_lenth : data_lenth])
    return fragmented_data
