import { useId } from "react";

interface BrandLogoProps {
  /**
   * "monochrome" (< 48px: TitleBar, Tray Popover header) renders the 24x24
   * De Casteljau physical-cut Overpass X in currentColor (0 mask, 0 filter).
   * "color" (>= 48px ONLY: Settings About card, empty states) renders the
   * pure-vector 0-filter Variant A Full-Rainbow Overpass X G2 Squircle.
   */
  variant?: "monochrome" | "color";
  className?: string;
}

const MACOS_SQUIRCLE_PATH =
  "M 512 100 L 702 100 C 842 100 924 182 924 322 L 924 702 C 924 842 842 924 702 924 L 322 924 C 182 924 100 842 100 702 L 100 322 C 100 182 182 100 322 100 Z";

const OVERPASS_LOWER_PATH =
  "M 318 346 C 390 346 446 446 512 512 C 578 578 634 678 706 678";

const OVERPASS_UPPER_PATH =
  "M 318 678 C 390 678 446 578 512 512 C 578 446 634 346 706 346";

// Authoritative 24x24 De Casteljau physical split (gap=standard, trayCutT=0.60)
const TRAY_LOWER_LEFT = "M 3.40 5.80 C 5.44 5.80 7.18 7.02 8.70 8.58";
const TRAY_LOWER_RIGHT = "M 15.30 15.42 C 16.82 16.98 18.56 18.20 20.60 18.20";
const TRAY_UPPER = "M 3.4 18.2 C 6.8 18.2 9.2 14.8 12 12 C 14.8 9.2 17.2 5.8 20.6 5.8";

export function BrandLogo({
  variant = "monochrome",
  className = "h-[18px] w-[18px]",
}: BrandLogoProps) {
  const rawId = useId();
  const uid = `bx-${rawId.replace(/[^a-zA-Z0-9_-]/g, "")}`;

  if (variant === "monochrome") {
    return (
      <svg
        className={className}
        viewBox="0 0 24 24"
        fill="none"
        aria-hidden="true"
      >
        <path
          d={TRAY_LOWER_LEFT}
          stroke="currentColor"
          strokeWidth="2.65"
          strokeLinecap="round"
        />
        <path
          d={TRAY_LOWER_RIGHT}
          stroke="currentColor"
          strokeWidth="2.65"
          strokeLinecap="round"
        />
        <path
          d={TRAY_UPPER}
          stroke="currentColor"
          strokeWidth="2.75"
          strokeLinecap="round"
        />
      </svg>
    );
  }

  // Sole component authorized by DESIGN.md G10 to hold Variant A 105%-sat rainbow hexes.
  return (
    <svg
      className={className}
      viewBox="0 0 1024 1024"
      fill="none"
      aria-hidden="true"
    >
      <defs>
        <linearGradient
          id={`${uid}-sq-bg`}
          x1="120"
          y1="100"
          x2="900"
          y2="924"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0%" stopColor="#FFFFFF" />
          <stop offset="72%" stopColor="#FDFEFF" />
          <stop offset="100%" stopColor="#F4F7FB" />
        </linearGradient>
        <mask
          id={`${uid}-mask-lower`}
          maskUnits="userSpaceOnUse"
          x="180"
          y="180"
          width="664"
          height="664"
        >
          <path
            d={OVERPASS_LOWER_PATH}
            fill="none"
            stroke="#FFFFFF"
            strokeWidth="108"
            strokeLinecap="round"
          />
          <path
            d={OVERPASS_UPPER_PATH}
            fill="none"
            stroke="black"
            strokeWidth="176"
            strokeLinecap="round"
          />
        </mask>
        <linearGradient
          id={`${uid}-vec-lower`}
          x1="300"
          y1="320"
          x2="720"
          y2="700"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0%" stopColor="#46E27F" />
          <stop offset="35%" stopColor="#FFCF10" />
          <stop offset="68%" stopColor="#3681FB" />
          <stop offset="100%" stopColor="#33BFFD" />
        </linearGradient>
        <linearGradient
          id={`${uid}-vec-upper`}
          x1="300"
          y1="690"
          x2="720"
          y2="330"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0%" stopColor="#33BFFD" />
          <stop offset="28%" stopColor="#46E27F" />
          <stop offset="52%" stopColor="#FFCF10" />
          <stop offset="76%" stopColor="#FF9238" />
          <stop offset="100%" stopColor="#F93A5B" />
        </linearGradient>
        <radialGradient
          id={`${uid}-vec-highlight`}
          cx="512"
          cy="512"
          r="240"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0%" stopColor="#3681FB" stopOpacity="0.34" />
          <stop offset="100%" stopColor="#3681FB" stopOpacity="0" />
        </radialGradient>
      </defs>

      <g>
        <path
          d={MACOS_SQUIRCLE_PATH}
          transform="translate(0 12)"
          fill="#0F172A"
          fillOpacity="0.07"
        />
        <path d={MACOS_SQUIRCLE_PATH} fill={`url(#${uid}-sq-bg)`} />
        <path
          d={MACOS_SQUIRCLE_PATH}
          fill="none"
          stroke="#E2E8F0"
          strokeWidth="4"
        />
      </g>

      <g>
        <g mask={`url(#${uid}-mask-lower)`}>
          <path
            d={OVERPASS_LOWER_PATH}
            fill="none"
            stroke={`url(#${uid}-vec-lower)`}
            strokeWidth="108"
            strokeLinecap="round"
          />
        </g>
        <g>
          <path
            d={OVERPASS_UPPER_PATH}
            fill="none"
            stroke={`url(#${uid}-vec-upper)`}
            strokeWidth="108"
            strokeLinecap="round"
          />
          <path
            d={OVERPASS_UPPER_PATH}
            fill="none"
            stroke={`url(#${uid}-vec-highlight)`}
            strokeWidth="108"
            strokeLinecap="round"
          />
        </g>
      </g>
    </svg>
  );
}
