/** How many rows a very long list shows at first, and how many more each click adds. */
export const LIST_STEP = 5000
/**
 * The most a list ever shows. Browsers cannot make a page taller than about
 * 33 million pixels, and every row measured in a very long list makes the
 * virtualizer walk the rest of it, so beyond this the useful thing is to
 * narrow the list with the filters or to export it.
 */
export const LIST_MAX = 50_000
