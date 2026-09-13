import React from "react";

const iconProps = { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "1.6", strokeLinecap: "round", strokeLinejoin: "round" };

export const IconSearch = (p) => <svg {...iconProps} {...p}><circle cx="11" cy="11" r="7" /><line x1="21" y1="21" x2="16.5" y2="16.5" /></svg>;
export const IconLock = (p) => <svg {...iconProps} {...p}><rect x="4.5" y="10.5" width="15" height="9.5" rx="2.5" /><path d="M7.5 10.5V7a4.5 4.5 0 0 1 9 0v3.5" /></svg>;
export const IconArrow = (p) => <svg {...iconProps} {...p} strokeWidth="1.8"><line x1="4" y1="12" x2="19" y2="12" /><polyline points="13 6 19 12 13 18" /></svg>;