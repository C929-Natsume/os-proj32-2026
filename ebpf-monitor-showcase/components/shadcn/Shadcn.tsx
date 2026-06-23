"use client";

import { MenuIcon, ShareIcon } from "lucide-react";
import type { TooltipContentProps } from "@radix-ui/react-tooltip";
import Image from "next/image";
import { ComponentPropsWithRef, type FC } from "react";

import { Button } from "@/components/ui/button";
import icon from "@/public/favicon/icon.svg";
import { Sheet, SheetContent, SheetTrigger } from "../ui/sheet";
import { Tooltip, TooltipContent, TooltipTrigger } from "../ui/tooltip";
import { ModelPicker } from "./ModelPicker";
import { DatabasePicker } from "./DatabasePicker";
import { SchemaPicker } from "./SchemaPicker";
import { ThreadList } from "@/components/assistant-ui/thread-list";

type ButtonWithTooltipProps = ComponentPropsWithRef<typeof Button> & {
  tooltip: string;
  side?: TooltipContentProps["side"];
};

const ButtonWithTooltip: FC<ButtonWithTooltipProps> = ({
  children,
  tooltip,
  side = "top",
  ...rest
}) => {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button {...rest}>
          {children}
          <span className="sr-only">{tooltip}</span>
        </Button>
      </TooltipTrigger>
      <TooltipContent side={side}>{tooltip}</TooltipContent>
    </Tooltip>
  );
};

const TopLeft: FC = () => {
  return (
    <div className="flex h-full w-full items-center gap-2 px-3 text-sm font-semibold">
      <Image
        src={icon}
        alt="logo"
        className="inline size-4 dark:hue-rotate-180 dark:invert"
      />
      <span>assistant-ui</span>
    </div>
  );
};

const MainLeft: FC = () => {
  return <ThreadList />;
};

const LeftBarSheet: FC = () => {
  return (
    <Sheet>
      <SheetTrigger asChild>
        <Button variant="outline" size="icon" className="shrink-0 md:hidden">
          <MenuIcon className="size-4" />
          <span className="sr-only">Toggle navigation menu</span>
        </Button>
      </SheetTrigger>
      <SheetContent side="left" className="flex flex-col">
        <div className="mt-6 flex flex-col gap-1">
          <TopLeft />
          <MainLeft />
        </div>
      </SheetContent>
    </Sheet>
  );
};

const Header: FC = () => {
  return (
    <header className="flex w-full items-center justify-between gap-2">
      <div className="flex items-center gap-5">
        <LeftBarSheet />
        <ModelPicker />
        <DatabasePicker />
        <SchemaPicker />
      </div>
      <ButtonWithTooltip
        variant="outline"
        size="icon"
        tooltip="Share"
        side="bottom"
        className="shrink-0"
      >
        <ShareIcon className="size-4" />
      </ButtonWithTooltip>
    </header>
  );
};

export const Shadcn: FC = () => {
  return <Header />;
};
