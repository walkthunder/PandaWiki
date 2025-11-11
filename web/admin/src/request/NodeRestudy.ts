/* eslint-disable */
/* tslint:disable */
// @ts-nocheck
/*
 * ---------------------------------------------------------------
 * ## THIS FILE WAS GENERATED VIA SWAGGER-TYPESCRIPT-API        ##
 * ##                                                           ##
 * ## AUTHOR: acacode                                           ##
 * ## SOURCE: https://github.com/acacode/swagger-typescript-api ##
 * ---------------------------------------------------------------
 */

import httpRequest, { ContentType, RequestParams } from "./httpClient";
import { DomainResponse, V1NodeRestudyReq, V1NodeRestudyResp } from "./types";

/**
 * @description 文档重新学习
 *
 * @tags NodeRestudy
 * @name PostApiV1NodeRestudy
 * @summary 文档重新学习
 * @request POST:/api/v1/node/restudy
 * @secure
 * @response `200` `(DomainResponse & {
    data?: V1NodeRestudyResp,

})` OK
 */

export const postApiV1NodeRestudy = (
  param: V1NodeRestudyReq,
  params: RequestParams = {},
) =>
  httpRequest<
    DomainResponse & {
      data?: V1NodeRestudyResp;
    }
  >({
    path: `/api/v1/node/restudy`,
    method: "POST",
    body: param,
    secure: true,
    type: ContentType.Json,
    format: "json",
    ...params,
  });
