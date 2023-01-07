//! This module mainly implements the inference-attack family. This contains the frequency analysis, l_p optimization as well as the (scaled) MLE attack.
//! This module should be enabled by the `attack` feature.

use pathfinding::kuhn_munkres::kuhn_munkres_min;
