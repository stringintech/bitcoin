# windowviz

Renders a video of the connect window from a node's `debug.log`: the blocks in the window at each moment of
the node's own clock, lowest height on the left, each box coloured by the block's phase and as tall as its
input count (log scale). Below it, the number of blocks in the window over the rendered range.

## Producing the log

Run the node with the `window` log category, for example a reindex of the chainstate:

```
bitcoind -signet -reindex-chainstate -debug=window
```

Each window block logs one `window-c` line when it is published.

## Rendering

Needs Python 3, [Pillow](https://pypi.org/project/pillow/) and `ffmpeg` on the `PATH`.

```
contrib/windowviz/windowviz.py debug.log --from 264000 --to 265000 -o window.mp4
```

| Argument | Default | Meaning |
|---|---|---|
| `log` | (required) | a `debug.log` written with `-debug=window` |
| `--from H` | 0 | lowest height to render |
| `--to H` | all | highest height to render |
| `--speed S` | 0.05 | node seconds per video second (1/20 of real time) |
| `-o FILE` | `window.mp4` | the output video |

Set `--from` and `--to`: a whole sync at the default speed is hours of video. If the log holds several starts
of the node, the last one is used.

## Colours

Saturated: a worker is on the block. Pale: the block holds a window slot and no core works on it.

| Colour | Phase |
|---|---|
| lavender | reading the block from disk |
| grey | queued for a worker |
| teal | parsing, entering its outputs in the window table |
| pale teal | waiting for the lower blocks' outputs |
| blue | validating |
| pale orange | valid, waiting for its commit |
| orange | committing to the coin store |
| green | committed, waiting to be published |

`t` at the top of a frame is the node's time in seconds since the first block of the rendered range was
staged.
